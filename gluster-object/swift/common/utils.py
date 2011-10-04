# Copyright (c) 2010 OpenStack, LLC.
# Copyright (c) 2011 Gluster, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Miscellaneous utility functions for use with Swift."""

import errno
import fcntl
import os
import pwd
import signal
import sys
import time
import mimetools
from hashlib import md5
from random import shuffle
from urllib import quote
from contextlib import contextmanager
import ctypes
import ctypes.util
import struct
from ConfigParser import ConfigParser, NoSectionError, NoOptionError
from optparse import OptionParser
from tempfile import mkstemp
import cPickle as pickle
import glob
from urlparse import urlparse as stdlib_urlparse, ParseResult
from xattr import getxattr, setxattr, removexattr

import eventlet
from eventlet import greenio, GreenPool, sleep, Timeout, listen
from eventlet.green import socket, subprocess, ssl, thread, threading
import netifaces

from swift.common.constraints import check_utf8
from swift.common.exceptions import LockTimeout, MessageTimeout, ObjectError, \
     ContainerError, AccountError
from swift.common.constraints import check_mount

# logging doesn't import patched as cleanly as one would like
from logging.handlers import SysLogHandler
import logging
logging.thread = eventlet.green.thread
logging.threading = eventlet.green.threading
logging._lock = logging.threading.RLock()
# setup notice level logging
NOTICE = 25
logging._levelNames[NOTICE] = 'NOTICE'
SysLogHandler.priority_map['NOTICE'] = 'notice'

#TODO : Use these macros as metadata keys for storing metadata as xattr.
X_CONTENT_TYPE = 'X-Content-Type'
X_CONTENT_LENGTH = 'X-Content-Length'
X_TIMESTAMP = 'X-Timestamp'
X_PUT_TIMESTAMP = 'X-PUT-Timestamp'
X_TYPE = 'X-Type'
X_ETAG = 'X-ETag'
X_OBJECTS_COUNT = 'X-Object-Count'
X_BYTES_USED = 'X-Bytes-Used'
X_CONTAINER_COUNT = 'X-Container-Count'
X_OBJECT_TYPE = 'X-Object-Type'

VERSION_STRING = 'UFO-1.0'

DIR = 'dir'
MARKER_DIR = 'marker_dir'
FILE = 'file'

DIR_TYPE = 'application/directory'
FILE_TYPE = 'application/octet-stream'

OBJECT_SERVER_IP = '127.0.0.1'
OBJECT_SERVER_PORT = 6010
CONTAINER_SERVER_IP = '127.0.0.1'
CONTAINER_SERVER_PORT = 6011
ACCOUNT_SERVER_IP = '127.0.0.1'
ACCOUNT_SERVER_PORT = 6012

RESELLER_PREFIX = 'AUTH_'
AUTH_ACCOUNT = 'auth'
REPLICA_COUNT = 1

MOUNT_PATH = '/mnt/gluster-object'
MOUNT_IP = 'localhost'

OBJECT = 'Object'
CONTAINER = 'Container'
ACCOUNT = 'Account'

DEFAULT_UID = -1
DEFAULT_GID = -1

CHUNK_SIZE = 65536

global_headers = ['uid', 'gid']

PICKLE_PROTOCOL = 2
METADATA_KEY = 'user.swift.metadata'

# These are lazily pulled from libc elsewhere
_sys_fallocate = None
_posix_fadvise = None

# Used by hash_path to offer a bit more security when generating hashes for
# paths. It simply appends this value to all paths; guessing the hash a path
# will end up with would also require knowing this suffix.
hash_conf = ConfigParser()
HASH_PATH_SUFFIX = ''
if hash_conf.read('/etc/gluster-object/gluster-object.conf'):
    try:
        HASH_PATH_SUFFIX = hash_conf.get('swift-hash',
                                         'swift_hash_path_suffix')
    except (NoSectionError, NoOptionError):
        pass

_fs_conf = ConfigParser()
_fs_conf.read(os.path.join('/etc/gluster-object', 'fs.conf'))
_mount_path = _fs_conf.get('DEFAULT', 'mount_path', '/mnt/gluster-object')

# Used when reading config values
TRUE_VALUES = set(('true', '1', 'yes', 'on', 't', 'y', 'True', 'Yes', 'On', 'T',
        'Y'))

# Used with xml.sax.saxutils.escape
XML_EXTRA_ENTITIES = dict((chr(x), '&#x%x;' % x) for x in xrange(1, 0x20))

def validate_configuration():
    if HASH_PATH_SUFFIX == '':
        sys.exit("Error: [swift-hash]: swift_hash_path_suffix missing "
                 "from /etc/gluster-object/gluster-object.conf")

def strip_obj_storage_path(path, string=_mount_path):
        """
        strip /mnt/gluster-object
        """
        return path.replace(string, '').strip('/')

def load_libc_function(func_name):
    """
    Attempt to find the function in libc, otherwise return a no-op func.

    :param func_name: name of the function to pull from libc.
    """
    try:
        libc = ctypes.CDLL(ctypes.util.find_library('c'))
        return getattr(libc, func_name)
    except AttributeError:
        logging.warn(_("Unable to locate %s in libc.  Leaving as a no-op."),
                     func_name)

        def noop_libc_function(*args):
            return 0
        return noop_libc_function


def get_param(req, name, default=None):
    """
    Get parameters from an HTTP request ensuring proper handling UTF-8
    encoding.

    :param req: Webob request object
    :param name: parameter name
    :param default: result to return if the parameter is not found
    :returns: HTTP request parameter value
    """
    value = req.str_params.get(name, default)
    if value and not check_utf8(value):
        raise ValueError('Not valid UTF-8 or contains NULL characters')
    return value



def fallocate(fd, size):
    """
    Pre-allocate disk space for a file file.

    :param fd: file descriptor
    :param size: size to allocate (in bytes)
    """
    global _sys_fallocate
    if _sys_fallocate is None:
        _sys_fallocate = load_libc_function('fallocate')
    if size > 0:
        # 1 means "FALLOC_FL_KEEP_SIZE", which means it pre-allocates invisibly
        ret = _sys_fallocate(fd, 1, 0, ctypes.c_uint64(size))
        # XXX: in (not very thorough) testing, errno always seems to be 0?
        err = ctypes.get_errno()
        if ret and err not in (0, errno.ENOSYS):
            raise OSError(err, 'Unable to fallocate(%s)' % size)


def drop_buffer_cache(fd, offset, length):
    """
    Drop 'buffer' cache for the given range of the given file.

    :param fd: file descriptor
    :param offset: start offset
    :param length: length
    """
    global _posix_fadvise
    if _posix_fadvise is None:
        _posix_fadvise = load_libc_function('posix_fadvise64')
    # 4 means "POSIX_FADV_DONTNEED"
    ret = _posix_fadvise(fd, ctypes.c_uint64(offset),
                        ctypes.c_uint64(length), 4)
    if ret != 0:
        logging.warn("posix_fadvise64(%s, %s, %s, 4) -> %s"
                     % (fd, offset, length, ret))        


def normalize_timestamp(timestamp):
    """
    Format a timestamp (string or numeric) into a standardized
    xxxxxxxxxx.xxxxx format.

    :param timestamp: unix timestamp
    :returns: normalized timestamp as a string
    """
    return "%016.05f" % (float(timestamp))


def mkdirs(path):
    """
    Ensures the path is a directory or makes it if not. Errors if the path
    exists but is a file or on permissions failure.

    :param path: path to create
    """
    if not os.path.isdir(path):
        try:
            do_makedirs(path)
        except OSError, err:
            #TODO: check, isdir will fail if mounted and volume stopped.
            #if err.errno != errno.EEXIST or not os.path.isdir(path)
            if err.errno != errno.EEXIST:
                raise

def dir_empty(path):
    return not do_listdir(path)
    
def rmdirs(path):
    if os.path.isdir(path) and dir_empty(path):
        do_rmdir(path)
    else:
        logging.error("rmdirs failed dir may not be empty or not valid dir")
        return False
        

def remove_dir_path(path, container_path):
    if path:
        obj_dirs = path.split('/')
        tmp_path = path
        if len(obj_dirs):
            while tmp_path:
                #TODO: Check dir is empty (Done in rmdirs)
                dir_path = os.path.join(container_path, tmp_path)
                rmdirs(dir_path)
                if '/' in tmp_path:
                    tmp_path = tmp_path.rsplit('/', 1)[0]
                else:
                    break
    

def renamer(old, new):
    """
    Attempt to fix / hide race conditions like empty object directories
    being removed by backend processes during uploads, by retrying.

    :param old: old path to be renamed
    :param new: new path to be renamed to
    """
        
    try:
        mkdirs(os.path.dirname(new))
        do_rename(old, new)
    except OSError:
        mkdirs(os.path.dirname(new))
        do_rename(old, new)
        
    
def split_path(path, minsegs=1, maxsegs=None, rest_with_last=False):
    """
    Validate and split the given HTTP request path.

    **Examples**::

        ['a'] = split_path('/a')
        ['a', None] = split_path('/a', 1, 2)
        ['a', 'c'] = split_path('/a/c', 1, 2)
        ['a', 'c', 'o/r'] = split_path('/a/c/o/r', 1, 3, True)

    :param path: HTTP Request path to be split
    :param minsegs: Minimum number of segments to be extracted
    :param maxsegs: Maximum number of segments to be extracted
    :param rest_with_last: If True, trailing data will be returned as part
                           of last segment.  If False, and there is
                           trailing data, raises ValueError.
    :returns: list of segments with a length of maxsegs (non-existant
              segments will return as None)
    :raises: ValueError if given an invalid path
    """
    if not maxsegs:
        maxsegs = minsegs
    if minsegs > maxsegs:
        raise ValueError('minsegs > maxsegs: %d > %d' % (minsegs, maxsegs))
    if rest_with_last:
        segs = path.split('/', maxsegs)
        minsegs += 1
        maxsegs += 1
        count = len(segs)
        if segs[0] or count < minsegs or count > maxsegs or \
           '' in segs[1:minsegs]:
            raise ValueError('Invalid path: %s' % quote(path))
    else:
        minsegs += 1
        maxsegs += 1
        segs = path.split('/', maxsegs)
        count = len(segs)
        if segs[0] or count < minsegs or count > maxsegs + 1 or \
           '' in segs[1:minsegs] or (count == maxsegs + 1 and segs[maxsegs]):
            raise ValueError('Invalid path: %s' % quote(path))
    segs = segs[1:maxsegs]
    segs.extend([None] * (maxsegs - 1 - len(segs)))
    return segs


class NullLogger():
    """A no-op logger for eventlet wsgi."""

    def write(self, *args):
        #"Logs" the args to nowhere
        pass


class LoggerFileObject(object):

    def __init__(self, logger):
        self.logger = logger

    def write(self, value):
        value = value.strip()
        if value:
            if 'Connection reset by peer' in value:
                self.logger.error(_('STDOUT: Connection reset by peer'))
            else:
                self.logger.error(_('STDOUT: %s'), value)

    def writelines(self, values):
        self.logger.error(_('STDOUT: %s'), '#012'.join(values))

    def close(self):
        pass

    def flush(self):
        pass

    def __iter__(self):
        return self

    def next(self):
        raise IOError(errno.EBADF, 'Bad file descriptor')

    def read(self, size=-1):
        raise IOError(errno.EBADF, 'Bad file descriptor')

    def readline(self, size=-1):
        raise IOError(errno.EBADF, 'Bad file descriptor')

    def tell(self):
        return 0

    def xreadlines(self):
        return self


# double inheritance to support property with setter
class LogAdapter(logging.LoggerAdapter, object):
    """
    A Logger like object which performs some reformatting on calls to
    :meth:`exception`.  Can be used to store a threadlocal transaction id.
    """

    _txn_id = threading.local()

    def __init__(self, logger, server):
        logging.LoggerAdapter.__init__(self, logger, {})
        self.server = server
        setattr(self, 'warn', self.warning)

    @property
    def txn_id(self):
        if hasattr(self._txn_id, 'value'):
            return self._txn_id.value

    @txn_id.setter
    def txn_id(self, value):
        self._txn_id.value = value

    def getEffectiveLevel(self):
        return self.logger.getEffectiveLevel()

    def process(self, msg, kwargs):
        """
        Add extra info to message
        """
        kwargs['extra'] = {'server': self.server, 'txn_id': self.txn_id}
        return msg, kwargs

    def notice(self, msg, *args, **kwargs):
        """
        Convenience function for syslog priority LOG_NOTICE. The python
        logging lvl is set to 25, just above info.  SysLogHandler is
        monkey patched to map this log lvl to the LOG_NOTICE syslog
        priority.
        """
        self.log(NOTICE, msg, *args, **kwargs)

    def _exception(self, msg, *args, **kwargs):
        logging.LoggerAdapter.exception(self, msg, *args, **kwargs)

    def exception(self, msg, *args, **kwargs):
        _junk, exc, _junk = sys.exc_info()
        call = self.error
        emsg = ''
        if isinstance(exc, OSError):
            if exc.errno in (errno.EIO, errno.ENOSPC):
                emsg = str(exc)
            else:
                call = self._exception
        elif isinstance(exc, socket.error):
            if exc.errno == errno.ECONNREFUSED:
                emsg = _('Connection refused')
            elif exc.errno == errno.EHOSTUNREACH:
                emsg = _('Host unreachable')
            elif exc.errno == errno.ETIMEDOUT:
                emsg = _('Connection timeout')
            else:
                call = self._exception
        elif isinstance(exc, eventlet.Timeout):
            emsg = exc.__class__.__name__
            if hasattr(exc, 'seconds'):
                emsg += ' (%ss)' % exc.seconds
            if isinstance(exc, MessageTimeout):
                if exc.msg:
                    emsg += ' %s' % exc.msg
        else:
            call = self._exception
        call('%s: %s' % (msg, emsg), *args, **kwargs)


class TxnFormatter(logging.Formatter):
    """
    Custom logging.Formatter will append txn_id to a log message if the record
    has one and the message does not.
    """

    def format(self, record):
        msg = logging.Formatter.format(self, record)
        if (record.txn_id and record.levelno != logging.INFO and
            record.txn_id not in msg):
            msg = "%s (txn: %s)" % (msg, record.txn_id)
        return msg


def get_logger(conf, name=None, log_to_console=False, log_route=None,
               fmt="%(server)s %(message)s"):
    """
    Get the current system logger using config settings.

    **Log config and defaults**::

        log_facility = LOG_LOCAL0
        log_level = INFO
        log_name = swift

    :param conf: Configuration dict to read settings from
    :param name: Name of the logger
    :param log_to_console: Add handler which writes to console on stderr
    :param log_route: Route for the logging, not emitted to the log, just used
                      to separate logging configurations
    :param fmt: Override log format
    """
    if not conf:
        conf = {}
    if name is None:
        name = conf.get('log_name', 'gluster-object')
    if not log_route:
        log_route = name
    logger = logging.getLogger(log_route)
    logger.propagate = False
    # all new handlers will get the same formatter
    formatter = TxnFormatter(fmt)

    # get_logger will only ever add one SysLog Handler to a logger
    if not hasattr(get_logger, 'handler4logger'):
        get_logger.handler4logger = {}
    if logger in get_logger.handler4logger:
        logger.removeHandler(get_logger.handler4logger[logger])

    # facility for this logger will be set by last call wins
    #facility = getattr(SysLogHandler, conf.get('log_facility', 'LOG_LOCAL0'),
                       #SysLogHandler.LOG_LOCAL0)
    facility = SysLogHandler.LOG_LOCAL0
    handler = SysLogHandler(address='/dev/log', facility=facility)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    get_logger.handler4logger[logger] = handler

    # setup console logging
    if log_to_console or hasattr(get_logger, 'console_handler4logger'):
        # remove pre-existing console handler for this logger
        if not hasattr(get_logger, 'console_handler4logger'):
            get_logger.console_handler4logger = {}
        if logger in get_logger.console_handler4logger:
            logger.removeHandler(get_logger.console_handler4logger[logger])

        console_handler = logging.StreamHandler(sys.__stderr__)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        get_logger.console_handler4logger[logger] = console_handler

    # set the level for the logger
    logger.setLevel(
        getattr(logging, conf.get('log_level', 'INFO').upper(), logging.INFO))
    adapted_logger = LogAdapter(logger, name)
    return adapted_logger


def drop_privileges(user):
    """
    Sets the userid/groupid of the current process, get session leader, etc.

    :param user: User name to change privileges to
    """
    user = pwd.getpwnam(user)
    os.setgid(user[3])
    os.setuid(user[2])
    try:
        os.setsid()
    except OSError:
        pass
    os.chdir('/')  # in case you need to rmdir on where you started the daemon
    os.umask(0)  # ensure files are created with the correct privileges


def capture_stdio(logger, **kwargs):
    """
    Log unhandled exceptions, close stdio, capture stdout and stderr.

    param logger: Logger object to use
    """
    # log uncaught exceptions
    sys.excepthook = lambda * exc_info: \
        logger.critical(_('UNCAUGHT EXCEPTION'), exc_info=exc_info)

    # collect stdio file desc not in use for logging
    stdio_files = [sys.stdin, sys.stdout, sys.stderr]
    console_fds = [h.stream.fileno() for _junk, h in getattr(
        get_logger, 'console_handler4logger', {}).items()]
    stdio_files = [f for f in stdio_files if f.fileno() not in console_fds]

    with open(os.devnull, 'r+b') as nullfile:
        # close stdio (excludes fds open for logging)
        for f in stdio_files:
            f.flush()
            try:
                os.dup2(nullfile.fileno(), f.fileno())
            except OSError:
                pass

    # redirect stdio
    if kwargs.pop('capture_stdout', True):
        sys.stdout = LoggerFileObject(logger)
    if kwargs.pop('capture_stderr', True):
        sys.stderr = LoggerFileObject(logger)


def parse_options(parser=None, once=False, test_args=None):
    """
    Parse standard swift server/daemon options with optparse.OptionParser.

    :param parser: OptionParser to use. If not sent one will be created.
    :param once: Boolean indicating the "once" option is available
    :param test_args: Override sys.argv; used in testing

    :returns : Tuple of (config, options); config is an absolute path to the
               config file, options is the parser options as a dictionary.

    :raises SystemExit: First arg (CONFIG) is required, file must exist
    """
    if not parser:
        parser = OptionParser(usage="%prog CONFIG [options]")
    parser.add_option("-v", "--verbose", default=False, action="store_true",
                      help="log to console")
    if once:
        parser.add_option("-o", "--once", default=False, action="store_true",
                          help="only run one pass of daemon")

    # if test_args is None, optparse will use sys.argv[:1]
    options, args = parser.parse_args(args=test_args)

    if not args:
        parser.print_usage()
        print _("Error: missing config file argument")
        sys.exit(1)
    config = os.path.abspath(args.pop(0))
    if not os.path.exists(config):
        parser.print_usage()
        print _("Error: unable to locate %s") % config
        sys.exit(1)

    extra_args = []
    # if any named options appear in remaining args, set the option to True
    for arg in args:
        if arg in options.__dict__:
            setattr(options, arg, True)
        else:
            extra_args.append(arg)

    options = vars(options)
    if extra_args:
        options['extra_args'] = extra_args
    return config, options


def whataremyips():
    """
    Get the machine's ip addresses

    :returns: list of Strings of ip addresses
    """
    addresses = []
    for interface in netifaces.interfaces():
        iface_data = netifaces.ifaddresses(interface)
        for family in iface_data:
            if family not in (netifaces.AF_INET, netifaces.AF_INET6):
                continue
            for address in iface_data[family]:
                addresses.append(address['addr'])
    return addresses


def storage_directory(datadir, partition, hash):
    """
    Get the storage directory

    :param datadir: Base data directory
    :param partition: Partition
    :param hash: Account, container or object hash
    :returns: Storage directory
    """
    return hash


def hash_path(account, container=None, object=None, raw_digest=False):
    """
    Get the connonical hash for an account/container/object

    :param account: Account
    :param container: Container
    :param object: Object
    :param raw_digest: If True, return the raw version rather than a hex digest
    :returns: hash string
    """
    if object and not container:
        raise ValueError('container is required if object is provided')
    paths = [account]
    if container:
        paths.append(container)
    if object:
        paths.append(object)
    if raw_digest:
        return md5('/' + '/'.join(paths) + HASH_PATH_SUFFIX).digest()
    else:
        return md5('/' + '/'.join(paths) + HASH_PATH_SUFFIX).hexdigest()


@contextmanager
def lock_path(directory, timeout=10):
    """
    Context manager that acquires a lock on a directory.  This will block until
    the lock can be acquired, or the timeout time has expired (whichever occurs
    first).

    :param directory: directory to be locked
    :param timeout: timeout (in seconds)
    """
    mkdirs(directory)
    fd = os.open(directory, os.O_RDONLY)
    try:
        with LockTimeout(timeout, directory):
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except IOError, err:
                    if err.errno != errno.EAGAIN:
                        raise
                sleep(0.01)
        yield True
    finally:
        os.close(fd)


def lock_parent_directory(filename, timeout=10):
    """
    Context manager that acquires a lock on the parent directory of the given
    file path.  This will block until the lock can be acquired, or the timeout
    time has expired (whichever occurs first).

    :param filename: file path of the parent directory to be locked
    :param timeout: timeout (in seconds)
    """
    return lock_path(os.path.dirname(filename), timeout=timeout)


def get_time_units(time_amount):
    """
    Get a nomralized length of time in the largest unit of time (hours,
    minutes, or seconds.)

    :param time_amount: length of time in seconds
    :returns: A touple of (length of time, unit of time) where unit of time is
              one of ('h', 'm', 's')
    """
    time_unit = 's'
    if time_amount > 60:
        time_amount /= 60
        time_unit = 'm'
        if time_amount > 60:
            time_amount /= 60
            time_unit = 'h'
    return time_amount, time_unit


def compute_eta(start_time, current_value, final_value):
    """
    Compute an ETA.  Now only if we could also have a progress bar...

    :param start_time: Unix timestamp when the operation began
    :param current_value: Current value
    :param final_value: Final value
    :returns: ETA as a tuple of (length of time, unit of time) where unit of
              time is one of ('h', 'm', 's')
    """
    elapsed = time.time() - start_time
    completion = (float(current_value) / final_value) or 0.00001
    return get_time_units(1.0 / completion * elapsed - elapsed)


def iter_devices_partitions(devices_dir, item_type):
    """
    Iterate over partitions accross all devices.

    :param devices_dir: Path to devices
    :param item_type: One of 'accounts', 'containers', or 'objects'
    :returns: Each iteration returns a tuple of (device, partition)
    """
    devices = do_listdir(devices_dir)
    shuffle(devices)
    devices_partitions = []
    for device in devices:
        partitions = do_listdir(os.path.join(devices_dir, device, item_type))
        shuffle(partitions)
        devices_partitions.append((device, iter(partitions)))
    yielded = True
    while yielded:
        yielded = False
        for device, partitions in devices_partitions:
            try:
                yield device, partitions.next()
                yielded = True
            except StopIteration:
                pass


def unlink_older_than(path, mtime):
    """
    Remove any file in a given path that that was last modified before mtime.

    :param path: path to remove file from
    :mtime: timestamp of oldest file to keep
    """
    if os.path.exists(path):
        for fname in do_listdir(path):
            fpath = os.path.join(path, fname)
            try:
                if os.path.getmtime(fpath) < mtime:
                    os.unlink(fpath)
            except OSError:
                pass


def item_from_env(env, item_name):
    """
    Get a value from the wsgi environment

    :param env: wsgi environment dict
    :param item_name: name of item to get

    :returns: the value from the environment
    """
    item = env.get(item_name, None)
    if item is None:
        logging.error("ERROR: %s could not be found in env!" % item_name)
    return item


def cache_from_env(env):
    """
    Get memcache connection pool from the environment (which had been
    previously set by the memcache middleware

    :param env: wsgi environment dict

    :returns: swift.common.memcached.MemcacheRing from environment
    """
    return item_from_env(env, 'swift.cache')


def readconf(conf, section_name=None, log_name=None, defaults=None):
    """
    Read config file and return config items as a dict

    :param conf: path to config file, or a file-like object (hasattr readline)
    :param section_name: config section to read (will return all sections if
                     not defined)
    :param log_name: name to be used with logging (will use section_name if
                     not defined)
    :param defaults: dict of default values to pre-populate the config with
    :returns: dict of config items
    """
    if defaults is None:
        defaults = {}
    c = ConfigParser(defaults)
    if hasattr(conf, 'readline'):
        c.readfp(conf)
    else:
        if not c.read(conf):
            print _("Unable to read config file %s") % conf
            sys.exit(1)
    if section_name:
        if c.has_section(section_name):
            conf = dict(c.items(section_name))
        else:
            print _("Unable to find %s config section in %s") % \
                 (section_name, conf)
            sys.exit(1)
        if "log_name" not in conf:
            if log_name is not None:
                conf['log_name'] = log_name
            else:
                conf['log_name'] = section_name
    else:
        conf = {}
        for s in c.sections():
            conf.update({s: dict(c.items(s))})
        if 'log_name' not in conf:
            conf['log_name'] = log_name
    return conf


def write_pickle(obj, dest, tmp=None, pickle_protocol=0):
    """
    Ensure that a pickle file gets written to disk.  The file
    is first written to a tmp location, ensure it is synced to disk, then
    perform a move to its final location

    :param obj: python object to be pickled
    :param dest: path of final destination file
    :param tmp: path to tmp to use, defaults to None
    :param pickle_protocol: protocol to pickle the obj with, defaults to 0
    """
    if tmp == None:
        tmp = os.path.dirname(dest)
    fd, tmppath = mkstemp(dir=tmp, suffix='.tmp')
    with os.fdopen(fd, 'wb') as fo:
        pickle.dump(obj, fo, pickle_protocol)
        fo.flush()
        os.fsync(fd)
        renamer(tmppath, dest)


def search_tree(root, glob_match, ext):
    """Look in root, for any files/dirs matching glob, recurively traversing
    any found directories looking for files ending with ext

    :param root: start of search path
    :param glob_match: glob to match in root, matching dirs are traversed with
                       os.walk
    :param ext: only files that end in ext will be returned

    :returns: list of full paths to matching files, sorted

    """
    found_files = []
    for path in glob.glob(os.path.join(root, glob_match)):
        if path.endswith(ext):
            found_files.append(path)
        else:
            for root, dirs, files in os.walk(path):
                for file in files:
                    if file.endswith(ext):
                        found_files.append(os.path.join(root, file))
    return sorted(found_files)


def write_file(path, contents):
    """Write contents to file at path

    :param path: any path, subdirs will be created as needed
    :param contents: data to write to file, will be converted to string

    """
    dirname, name = os.path.split(path)
    if not os.path.exists(dirname):
        try:
            os.makedirs(dirname)
        except OSError, err:
            if err.errno == errno.EACCES:
                sys.exit('Unable to create %s.  Running as '
                         'non-root?' % dirname)
    with open(path, 'w') as f:
        f.write('%s' % contents)


def remove_file(path):
    """Quiet wrapper for os.unlink, OSErrors are suppressed

    :param path: first and only argument passed to os.unlink
    """
    try:
        os.unlink(path)
    except OSError:
        pass


def audit_location_generator(devices, datadir, mount_check=True, logger=None):
    '''
    Given a devices path and a data directory, yield (path, device,
    partition) for all files in that directory

    :param devices: parent directory of the devices to be audited
    :param datadir: a directory located under self.devices. This should be
                    one of the DATADIR constants defined in the account,
                    container, and object servers.
    :param mount_check: Flag to check if a mount check should be performed
                    on devices
    :param logger: a logger object
    '''
    device_dir = do_listdir(devices)
    # randomize devices in case of process restart before sweep completed
    shuffle(device_dir)
    for device in device_dir:
        if mount_check and not \
                os.path.ismount(os.path.join(devices, device)):
            if logger:
                logger.debug(
                    _('Skipping %s as it is not mounted'), device)
            continue
        datadir_path = os.path.join(devices, device, datadir)
        if not os.path.exists(datadir_path):
            continue
        partitions = do_listdir(datadir_path)
        for partition in partitions:
            part_path = os.path.join(datadir_path, partition)
            if not os.path.isdir(part_path):
                continue
            suffixes = do_listdir(part_path)
            for suffix in suffixes:
                suff_path = os.path.join(part_path, suffix)
                if not os.path.isdir(suff_path):
                    continue
                hashes = do_listdir(suff_path)
                for hsh in hashes:
                    hash_path = os.path.join(suff_path, hsh)
                    if not os.path.isdir(hash_path):
                        continue
                    for fname in sorted(do_listdir(hash_path),
                                        reverse=True):
                        path = os.path.join(hash_path, fname)
                        yield path, device, partition


def ratelimit_sleep(running_time, max_rate, incr_by=1, rate_buffer=5):
    '''
    Will eventlet.sleep() for the appropriate time so that the max_rate
    is never exceeded.  If max_rate is 0, will not ratelimit.  The
    maximum recommended rate should not exceed (1000 * incr_by) a second
    as eventlet.sleep() does involve some overhead.  Returns running_time
    that should be used for subsequent calls.

    :param running_time: the running time of the next allowable request. Best
                         to start at zero.
    :param max_rate: The maximum rate per second allowed for the process.
    :param incr_by: How much to increment the counter.  Useful if you want
                    to ratelimit 1024 bytes/sec and have differing sizes
                    of requests. Must be >= 0.
    :param rate_buffer: Number of seconds the rate counter can drop and be
                        allowed to catch up (at a faster than listed rate).
                        A larger number will result in larger spikes in rate
                        but better average accuracy.
    '''
    if not max_rate or incr_by <= 0:
        return running_time
    clock_accuracy = 1000.0
    now = time.time() * clock_accuracy
    time_per_request = clock_accuracy * (float(incr_by) / max_rate)
    if now - running_time > rate_buffer * clock_accuracy:
        running_time = now
    elif running_time - now > time_per_request:
        eventlet.sleep((running_time - now) / clock_accuracy)
    return running_time + time_per_request


class ContextPool(GreenPool):
    "GreenPool subclassed to kill its coros when it gets gc'ed"

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        for coro in list(self.coroutines_running):
            coro.kill()


class ModifiedParseResult(ParseResult):
    "Parse results class for urlparse."

    @property
    def hostname(self):
        netloc = self.netloc.split('@', 1)[-1]
        if netloc.startswith('['):
            return netloc[1:].split(']')[0]
        elif ':' in netloc:
            return netloc.rsplit(':')[0]
        return netloc

    @property
    def port(self):
        netloc = self.netloc.split('@', 1)[-1]
        if netloc.startswith('['):
            netloc = netloc.rsplit(']')[1]
        if ':' in netloc:
            return int(netloc.rsplit(':')[1])
        return None


def urlparse(url):
    """
    urlparse augmentation.
    This is necessary because urlparse can't handle RFC 2732 URLs.

    :param url: URL to parse.
    """
    return ModifiedParseResult(*stdlib_urlparse(url))


def human_readable(value):
    """
    Returns the number in a human readable format; for example 1048576 = "1Mi".
    """
    value = float(value)
    index = -1
    suffixes = 'KMGTPEZY'
    while value >= 1024 and index + 1 < len(suffixes):
        index += 1
        value = round(value / 1024)
    if index == -1:
        return '%d' % value
    return '%d%si' % (round(value), suffixes[index])

def do_mkdir(path):
    try:
        os.mkdir(path)
    except Exception, err:
        logging.exception("Mkdir failed on %s err: %s", path, str(err))
        if err.errno != errno.EEXIST:
            raise
    return True

def do_makedirs(path):
    try:
        os.makedirs(path)
    except Exception, err:
        logging.exception("Makedirs failed on %s err: %s", path, str(err))
        if err.errno != errno.EEXIST:
            raise
    return True


def do_listdir(path):
    try:
        buf = os.listdir(path)
    except Exception, err:
        logging.exception("Listdir failed on %s err: %s", path, str(err))
        raise
    return buf

def do_chown(path, uid, gid):
    try:
        os.chown(path, uid, gid)
    except Exception, err:
        logging.exception("Chown failed on %s err: %s", path, str(err))
        raise
    return True

def do_stat(path):
    try:
        #Check for fd.
        if isinstance(path, int):
            buf = os.fstat(path)
        else:
            buf = os.stat(path)
    except Exception, err:
        logging.exception("Stat failed on %s err: %s", path, str(err))
        raise

    return buf

def do_open(path, mode):
    try:
        fd = open(path, mode)
    except Exception, err:
        logging.exception("Open failed on %s err: %s", path, str(err))
        raise
    return fd

def do_close(fd):
    #fd could be file or int type.
    try:
        if isinstance(fd, int):
            os.close(fd)
        else:
            fd.close()
    except Exception, err:
        logging.exception("Close failed on %s err: %s", fd, str(err))
        raise
    return True

def do_unlink(path, log = True):
    try:
        os.unlink(path)
    except Exception, err:
        if log:
            logging.exception("Unlink failed on %s err: %s", path, str(err))
        if err.errno != errno.ENOENT:
            raise
    return True

def do_rmdir(path):
    try:
        os.rmdir(path)
    except Exception, err:
        logging.exception("Rmdir failed on %s err: %s", path, str(err))
        if err.errno != errno.ENOENT:
            raise
    return True

def do_rename(old_path, new_path):
    try:
        os.rename(old_path, new_path)
    except Exception, err:
        logging.exception("Rename failed on %s to %s  err: %s", old_path, new_path, \
                          str(err))
        raise
    return True
        
def do_setxattr(path, key, value):
    fd = None
    if not os.path.isdir(path):
        fd = do_open(path, 'rb')
    else:
        fd = path
    if fd or os.path.isdir(path):
        try:
            setxattr(fd, key, value)
        except Exception, err:
            logging.exception("setxattr failed on %s key %s err: %s", path, key, str(err))
            raise
        finally:
            if fd and not os.path.isdir(path):
                do_close(fd)
    else:
        logging.error("Open failed path %s", path)
        return False
    return True
    
        

def do_getxattr(path, key, log = True):
    fd = None
    if not os.path.isdir(path):
        fd = do_open(path, 'rb')
    else:
        fd = path
    if fd or os.path.isdir(path):
        try:
            value = getxattr(fd, key)
        except Exception, err:
            if log:
                logging.exception("getxattr failed on %s key %s err: %s", path, key, str(err))
            raise
        finally:
            if fd and not os.path.isdir(path):
                do_close(fd)
    else:
        logging.error("Open failed path %s", path)
        return False
    return value

def do_removexattr(path, key):
    fd = None
    if not os.path.isdir(path):
        fd = do_open(path, 'rb')
    else:
        fd = path
    if fd or os.path.isdir(path):
        try:
            removexattr(fd, key)
        except Exception, err:
            logging.exception("removexattr failed on %s key %s err: %s", path, key, str(err))
            raise
        finally:
            if fd and not os.path.isdir(path):
                do_close(fd)
    else:
        logging.error("Open failed path %s", path)
        return False
    return True

def read_metadata(path):
    """
    Helper function to read the pickled metadata from a File/Directory .

    :param path: File/Directory to read metadata from.

    :returns: dictionary of metadata
    """
    metadata = ''
    key = 0
    while True:
        try:
            metadata += do_getxattr(path, '%s%s' % (METADATA_KEY, (key or '')),
                            log = False)
        except Exception:
            break
        key += 1
    if metadata:
        return pickle.loads(metadata)
    else:
        return metadata


def write_metadata(path, metadata):
    """
    Helper function to write pickled metadata for a File/Directory.

    :param path: File/Directory path to write the metadata
    :param metadata: metadata to write
    """
    metastr = pickle.dumps(metadata, PICKLE_PROTOCOL)
    key = 0
    while metastr:
        do_setxattr(path, '%s%s' % (METADATA_KEY, key or ''), metastr[:254])
        metastr = metastr[254:]
        key += 1

def clean_metadata(path):
    key = 0
    while True:
        value = do_getxattr(path, '%s%s' % (METADATA_KEY, (key or '')))
        do_removexattr(path, '%s%s' % (METADATA_KEY, (key or '')))
        key += 1


def dir_empty(path):
    """
    Return true if directory/container is empty.
    :param path: Directory path.
    :returns: True/False.
    """
    if os.path.isdir(path):
        try:
            files = do_listdir(path)
        except Exception, err:
            logging.exception("listdir failed on %s err: %s", path, str(err))
            raise
        if not files:
            return True
        else:
            return False


def get_device_from_account(account):
    if account.startswith(RESELLER_PREFIX):
        device = account.replace(RESELLER_PREFIX, '', 1)
        return device

def check_user_xattr(path):
    if not os.path.exists(path):
        return False
    do_setxattr(path, 'user.test.key1', 'value1')
    try:
        removexattr(path, 'user.test.key1')
    except Exception, err:
        logging.exception("removexattr failed on %s err: %s", path, str(err))
        #Remove xattr may fail in case of concurrent remove.
    return True

   
def _check_valid_account(account, fs_object):
    mount_path = getattr(fs_object, 'mount_path', MOUNT_PATH)
    
    if not check_account_exists(fs_object.get_export_from_account_id(account), \
                                fs_object):
        logging.error('Account not present %s', account)
        return False
    
    if not check_mount(mount_path, account):
        if not os.path.isdir(os.path.join(mount_path, account)):
            mkdirs(os.path.join(mount_path, account))

        fs_object.unmount(os.path.join(mount_path, account))
                    
    if fs_object:
        if not fs_object.mount(account):
            return False

    if not check_user_xattr(os.path.join(mount_path, account)):
        logging.error('Error: No support for user.xattr on backend %s' % account)
        return False

    chmod_cmd = ['chmod 777 %s' % (mount_path), \
                 'chmod 777 %s/%s' % (mount_path, account)]

    for cmd in chmod_cmd:
        if os.system(cmd):
            logging.error('Chmod failed: %s' % (cmd))
            return False
    
    return True

def check_valid_account(account, fs_object):
    return _check_valid_account(account, fs_object)

def validate_container(metadata):
    if not metadata:
        logging.error('No metadata')
        return False
    
    if X_TYPE not in metadata.keys() or \
       X_TIMESTAMP not in metadata.keys() or \
       X_PUT_TIMESTAMP not in metadata.keys() or \
       X_OBJECTS_COUNT not in metadata.keys() or \
       X_BYTES_USED not in metadata.keys():
        logging.error('Container error %s' % metadata)
        return False

    if metadata[X_TYPE] == CONTAINER:
        return True
    
    logging.error('Container error %s' % metadata)
    return False

def validate_account(metadata):
    if not metadata:
        logging.error('No metadata')
        return False
    
    if X_TYPE not in metadata.keys() or \
       X_TIMESTAMP not in metadata.keys() or \
       X_PUT_TIMESTAMP not in metadata.keys() or \
       X_OBJECTS_COUNT not in metadata.keys() or \
       X_BYTES_USED not in metadata.keys() or \
       X_CONTAINER_COUNT not in metadata.keys():
        logging.error('Account error %s' % metadata)
        return False

    if metadata[X_TYPE] == ACCOUNT:
        return True

    logging.error('Account error %s' % metadata)
    return False

def validate_object(metadata):
    if not metadata:
        logging.error('No metadata')
        return False
    
    if X_TIMESTAMP not in metadata.keys() or \
       X_CONTENT_TYPE not in metadata.keys() or \
       X_ETAG not in metadata.keys() or \
       X_CONTENT_LENGTH not in metadata.keys() or \
       X_TYPE not in metadata.keys() or \
       X_OBJECT_TYPE not in metadata.keys():
        logging.error('Object error %s' % metadata)
        return False

    if metadata[X_TYPE] == OBJECT:
        return True

    logging.error('Object error %s' % metadata)
    return False

def is_marker(metadata):
    if not metadata:
        logging.error('No metadata')
        return False
    
    if X_OBJECT_TYPE not in metadata.keys():
        logging.error('X_OBJECT_TYPE missing %s' % metadata)
        return False

    if metadata[X_OBJECT_TYPE] == MARKER_DIR:
        return True
    else:
        return False

def _update_list(path, const_path, src_list, reg_file=True, object_count=0,
                 bytes_used=0, obj_list=[]):
    obj_path = strip_obj_storage_path(path, const_path)

    for i in src_list:
        if obj_path:
            obj_list.append(os.path.join(obj_path, i))
        else:
            obj_list.append(i)

        object_count += 1

        if reg_file:
            bytes_used += os.path.getsize(path + '/' + i)

    return object_count, bytes_used

def update_list(path, const_path, dirs=[], files=[], object_count=0,
                bytes_used=0, obj_list=[]):
    object_count, bytes_used = _update_list (path, const_path, files, True,
                                             object_count, bytes_used,
                                             obj_list)
    object_count, bytes_used = _update_list (path, const_path, dirs, False,
                                             object_count, bytes_used,
                                             obj_list)
    return object_count, bytes_used

def get_container_details_from_fs(cont_path, const_path,
                                  memcache=None):
    """
    get container details by traversing the filesystem
    """
    bytes_used = 0
    object_count = 0
    obj_list=[]
    dir_list = []

    if os.path.isdir(cont_path):
        for (path, dirs, files) in os.walk(cont_path):
            object_count, bytes_used = update_list(path, const_path, dirs, files,
                                                   object_count, bytes_used,
                                                   obj_list)

            dir_list.append(path + ':' + str(do_stat(path).st_mtime))

    if memcache:
        memcache.set(strip_obj_storage_path(cont_path), obj_list)
        memcache.set(strip_obj_storage_path(cont_path) + '-dir_list',
                     ','.join(dir_list))
        memcache.set(strip_obj_storage_path(cont_path) + '-cont_meta',
                     [object_count, bytes_used])

    return obj_list, object_count, bytes_used

def get_container_details_from_memcache(cont_path, const_path,
                                        memcache):
    """
    get container details stored in memcache
    """

    bytes_used = 0
    object_count = 0
    obj_list=[]

    dir_contents = memcache.get(strip_obj_storage_path(cont_path) + '-dir_list')
    if not dir_contents:
        return get_container_details_from_fs(cont_path, const_path,
                                             memcache=memcache)

    for i in dir_contents.split(','):
        path, mtime = i.split(':')
        if mtime != str(do_stat(path).st_mtime):
            return get_container_details_from_fs(cont_path, const_path,
                                                 memcache=memcache)

    obj_list = memcache.get(strip_obj_storage_path(cont_path))

    object_count, bytes_used = memcache.get(strip_obj_storage_path(cont_path) + '-cont_meta')

    return obj_list, object_count, bytes_used

def get_container_details(cont_path, memcache=None):
    """
    Return object_list, object_count and bytes_used.
    """
    if memcache:
        object_list, object_count, bytes_used = get_container_details_from_memcache(cont_path, cont_path,
                                                                                    memcache=memcache)
    else:
        object_list, object_count, bytes_used = get_container_details_from_fs(cont_path, cont_path)

    return object_list, object_count, bytes_used

def get_account_details_from_fs(acc_path, memcache=None):
    container_list = []
    container_count = 0

    if os.path.isdir(acc_path):
        for name in do_listdir(acc_path):
            if not os.path.isdir(acc_path + '/' + name) or \
               name.lower() == 'tmp':
                continue
            container_count += 1
            container_list.append(name)

    if memcache:
        memcache.set(strip_obj_storage_path(acc_path) + '_container_list', container_list)
        memcache.set(strip_obj_storage_path(acc_path)+'_mtime', str(do_stat(acc_path).st_mtime))
        memcache.set(strip_obj_storage_path(acc_path)+'_container_count', container_count)

    return container_list, container_count

def get_account_details_from_memcache(acc_path, memcache=None):
    if memcache:
        mtime = memcache.get(strip_obj_storage_path(acc_path)+'_mtime')
        if not mtime or mtime != str(do_stat(acc_path).st_mtime):
            return get_account_details_from_fs(acc_path, memcache)
        container_list = memcache.get(strip_obj_storage_path(acc_path) + '_container_list')
        container_count = memcache.get(strip_obj_storage_path(acc_path)+'_container_count')
        return container_list, container_count
        
        

    


def get_account_details(acc_path, memcache=None):
    """
    Return container_list and container_count.
    """
    if memcache:
        return get_account_details_from_memcache(acc_path, memcache)
    else:
        return get_account_details_from_fs(acc_path, memcache)
        
    

def get_etag(path):
    etag = None
    if os.path.exists(path):
        etag = md5()
        if not os.path.isdir(path):
            fp = open(path, 'rb')
            if fp:
                while True:
                    chunk = fp.read(CHUNK_SIZE)
                    if chunk:
                        etag.update(chunk)
                    else:
                        break
                fp.close()

        etag = etag.hexdigest()

    return etag


def get_object_metadata(obj_path):
    """
    Return metadata of object.
    """
    metadata = {}
    if os.path.exists(obj_path):
        if not os.path.isdir(obj_path):
            metadata = {
                    X_TIMESTAMP: normalize_timestamp(os.path.getctime(obj_path)),
                    X_CONTENT_TYPE: FILE_TYPE,
                    X_ETAG: get_etag(obj_path),
                    X_CONTENT_LENGTH: os.path.getsize(obj_path),
                    X_TYPE: OBJECT,
                    X_OBJECT_TYPE: FILE,
                }
        else:
            metadata = {
                    X_TIMESTAMP: normalize_timestamp(os.path.getctime(obj_path)),
                    X_CONTENT_TYPE: DIR_TYPE,
                    X_ETAG: get_etag(obj_path),
                    X_CONTENT_LENGTH: 0,
                    X_TYPE: OBJECT,
                    X_OBJECT_TYPE: DIR,
                }

    return metadata

def get_container_metadata(cont_path, memcache=None):
    objects = []
    object_count = 0
    bytes_used = 0
    objects, object_count, bytes_used = get_container_details(cont_path,
                                                              memcache=memcache)
    metadata = {X_TYPE: CONTAINER,
                X_TIMESTAMP: normalize_timestamp(os.path.getctime(cont_path)),
                X_PUT_TIMESTAMP: normalize_timestamp(os.path.getmtime(cont_path)),
                X_OBJECTS_COUNT: object_count,
                X_BYTES_USED: bytes_used}
    return metadata

def get_account_metadata(acc_path, memcache=None):
    containers = []
    container_count = 0
    containers, container_count = get_account_details(acc_path, memcache)
    metadata = {X_TYPE: ACCOUNT,
                X_TIMESTAMP: normalize_timestamp(os.path.getctime(acc_path)),
                X_PUT_TIMESTAMP: normalize_timestamp(os.path.getmtime(acc_path)),
                X_OBJECTS_COUNT: 0,
                X_BYTES_USED: 0,
                X_CONTAINER_COUNT: container_count}
    return metadata

def restore_object(obj_path, metadata):
    write_metadata(obj_path, metadata)

def restore_container(cont_path, metadata):
    write_metadata(cont_path, metadata)

def restore_account(acc_path, metadata):
    write_metadata(acc_path, metadata)

def create_object_metadata(obj_path):
    meta = get_object_metadata(obj_path)
    restore_object(obj_path, meta)
    return meta

def create_container_metadata(cont_path, memcache=None):
    meta = get_container_metadata(cont_path, memcache)
    restore_container(cont_path, meta)
    return meta

def create_account_metadata(acc_path, memcache=None):
    meta = get_account_metadata(acc_path, memcache)
    restore_account(acc_path, meta)
    return meta


def check_account_exists(account, fs_object):
    if account not in get_account_list(fs_object):
        logging.error('Account not exists %s' % account)
        return False
    else:
        return True

def get_account_list(fs_object):
    account_list = []
    if fs_object:
        account_list = fs_object.get_export_list()
    return account_list


def get_account_id(account):
    return RESELLER_PREFIX + md5(account + HASH_PATH_SUFFIX).hexdigest()
    
