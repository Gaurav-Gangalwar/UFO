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

""" Object Server for Swift """

from __future__ import with_statement
import cPickle as pickle
import errno
import os
import time
import traceback
import uuid
from datetime import datetime
from hashlib import md5
from tempfile import mkstemp
from urllib import unquote
from contextlib import contextmanager

from webob import Request, Response, UTC
from webob.exc import HTTPAccepted, HTTPBadRequest, HTTPCreated, \
    HTTPInternalServerError, HTTPNoContent, HTTPNotFound, \
    HTTPNotModified, HTTPPreconditionFailed, \
    HTTPRequestTimeout, HTTPUnprocessableEntity, HTTPMethodNotAllowed

from eventlet import sleep, Timeout, TimeoutError, tpool

from swift.common.utils import mkdirs, normalize_timestamp, \
    storage_directory, hash_path, renamer, fallocate, \
    split_path, drop_buffer_cache, get_logger, write_pickle, \
    read_metadata, write_metadata, mkdirs, rmdirs, validate_object, \
    check_valid_account, create_object_metadata
from swift.common.bufferedhttp import http_connect
from swift.common.constraints import check_object_creation, check_mount, \
    check_float, check_utf8
from swift.common.exceptions import ConnectionTimeout, DiskFileError, \
    DiskFileNotExist
from swift.common.utils import X_CONTENT_TYPE, X_CONTENT_LENGTH, X_TIMESTAMP,\
     X_PUT_TIMESTAMP, X_TYPE, X_ETAG, X_OBJECTS_COUNT, X_BYTES_USED, \
     X_OBJECT_TYPE, FILE, DIR, MARKER_DIR, MOUNT_PATH, OBJECT, \
     RESELLER_PREFIX, DIR_TYPE, FILE_TYPE, DEFAULT_UID, DEFAULT_GID

import logging


DATADIR = 'objects'
ASYNCDIR = 'async_pending'
MAX_OBJECT_NAME_LENGTH = 1024
KEEP_CACHE_SIZE = (5 * 1024 * 1024)
# keep these lower-case
DISALLOWED_HEADERS = set('content-length content-type deleted etag'.split())


def quarantine_renamer(device_path, corrupted_file_path):
    """
    In the case that a file is corrupted, move it to a quarantined
    area to allow replication to fix it.

    :params device_path: The path to the device the corrupted file is on.
    :params corrupted_file_path: The path to the file you want quarantined.

    :returns: path (str) of directory the file was moved to
    :raises OSError: re-raises non errno.EEXIST / errno.ENOTEMPTY
                     exceptions from rename
    """
    from_dir = os.path.dirname(corrupted_file_path)
    to_dir = os.path.join(device_path, 'quarantined',
                          'objects', os.path.basename(from_dir))
    try:
        renamer(from_dir, to_dir)
    except OSError, e:
        if e.errno not in (errno.EEXIST, errno.ENOTEMPTY):
            raise
        to_dir = "%s-%s" % (to_dir, uuid.uuid4().hex)
        renamer(from_dir, to_dir)
    return to_dir


class DiskFile(object):
    """
    Manage object files on disk.

    :param path: path to devices on the node
    :param device: device name
    :param partition: partition on the device the object lives in
    :param account: account name for the object
    :param container: container name for the object
    :param obj: object name for the object
    :param keep_data_fp: if True, don't close the fp, otherwise close it
    :param disk_chunk_Size: size of chunks on file reads
    """

    def __init__(self, path, device, partition, account, container, obj,
                 logger, keep_data_fp=False, disk_chunk_size=65536, uid=DEFAULT_UID,
                 gid=DEFAULT_GID):
        self.disk_chunk_size = disk_chunk_size
        #Don't support obj_name ending/begining with '/', like /a, a/, /a/b/ etc
        obj = obj.strip('/')
        if '/' in obj:
            self.obj_path, self.obj = obj.rsplit('/', 1)
        else:
            self.obj_path = ''
            self.obj = obj
        
        if self.obj_path:
            self.name = '/'.join((container, self.obj_path))
        else:
            self.name = container
        
        self.datadir = os.path.join(path, device,
                    storage_directory(DATADIR, partition, self.name))
        
        self.device_path = os.path.join(path, device)
        self.container_path = os.path.join(path, device, container)
        self.tmpdir = os.path.join(path, device, 'tmp')
        self.logger = logger
        self.metadata = {}
        self.meta_file = None
        self.data_file = None
        self.fp = None
        self.iter_etag = None
        self.started_at_0 = False
        self.read_to_eof = False
        self.quarantined_dir = None
        self.keep_cache = False
        self.is_dir = False
        self.is_valid = True
        self.uid = int(uid)
        self.gid = int(gid)
        if not os.path.exists(self.datadir + '/' + self.obj):
            return
                
        self.data_file = os.path.join(self.datadir, self.obj)
        self.metadata = read_metadata(self.datadir + '/' + self.obj)
        if not self.metadata:
            create_object_metadata(self.datadir + '/' + self.obj)
            self.metadata = read_metadata(self.datadir + '/' + self.obj)
        if not validate_object(self.metadata):
            self.metadata = {}
            self.is_valid = False
            self.data_file = None
            return

        if os.path.isdir(self.datadir + '/' + self.obj):
            self.is_dir = True
        else:
            self.fp = open(self.data_file, 'rb')
            if not keep_data_fp:
                self.close(verify_file=False)
        
               
    def __iter__(self):
        """Returns an iterator over the data file."""
        try:
            dropped_cache = 0
            read = 0
            self.started_at_0 = False
            self.read_to_eof = False
            if self.fp.tell() == 0:
                self.started_at_0 = True
                self.iter_etag = md5()
            while True:
                chunk = self.fp.read(self.disk_chunk_size)
                if chunk:
                    if self.iter_etag:
                        self.iter_etag.update(chunk)
                    read += len(chunk)
                    if read - dropped_cache > (1024 * 1024):
                        self.drop_cache(self.fp.fileno(), dropped_cache,
                            read - dropped_cache)
                        dropped_cache = read
                    yield chunk
                else:
                    self.read_to_eof = True
                    self.drop_cache(self.fp.fileno(), dropped_cache,
                        read - dropped_cache)
                    break
        finally:
            self.close()

    def app_iter_range(self, start, stop):
        """Returns an iterator over the data file for range (start, stop)"""
        if start:
            self.fp.seek(start)
        if stop is not None:
            length = stop - start
        else:
            length = None
        for chunk in self:
            if length is not None:
                length -= len(chunk)
                if length < 0:
                    # Chop off the extra:
                    yield chunk[:length]
                    break
            yield chunk

    def _handle_close_quarantine(self):
        """Check if file needs to be quarantined"""
        try:
            obj_size = self.get_data_file_size()
        except DiskFileError, e:
            self.quarantine()
            return
        except DiskFileNotExist:
            return

        if (self.iter_etag and self.started_at_0 and self.read_to_eof and
            'ETag' in self.metadata and
            self.iter_etag.hexdigest() != self.metadata.get('ETag')):
                self.quarantine()

    def close(self, verify_file=True):
        """
        Close the file. Will handle quarantining file if necessary.

        :param verify_file: Defaults to True. If false, will not check
                            file to see if it needs quarantining.
        """
        #Marker directory
        if self.is_dir:
            return
        if self.fp:
            try:
                if verify_file:
                    self._handle_close_quarantine()
            except Exception, e:
                import traceback
                self.logger.error(_('ERROR DiskFile %(data_file)s in '
                     '%(data_dir)s close failure: %(exc)s : %(stack)'),
                     {'exc': e, 'stack': ''.join(traceback.format_stack()),
                      'data_file': self.data_file, 'data_dir': self.datadir})
            finally:
                self.fp.close()
                self.fp = None

    def is_deleted(self):
        """
        Check if the file is deleted.

        :returns: True if the file doesn't exist or has been flagged as
                  deleted.
        """
        return not self.data_file 

    @contextmanager
    def mkstemp(self):
        """Contextmanager to make a temporary file."""
        if not os.path.exists(self.tmpdir):
            mkdirs(self.tmpdir)
        fd, tmppath = mkstemp(dir=self.tmpdir)
        try:
            yield fd, tmppath
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                os.unlink(tmppath)
            except OSError:
                pass

    def create_dir_object(self, dir_name, timestamp):
        dir_path = os.path.join(self.container_path, dir_name)
        #TODO: if object already exists???
        if os.path.exists(dir_path) and not os.path.isdir(dir_path):
            os.unlink(dir_path)
        #If dir aleady exist just override metadata.
        mkdirs(dir_path)
        os.chown(dir_path, self.uid, self.gid)
        create_object_metadata(dir_path)
        return True

        

    def put_metadata(self, metadata):
        obj_path = self.datadir + '/' + self.obj
        write_metadata(obj_path, metadata)
        self.metadata = metadata
        

    def put(self, fd, tmppath, metadata, extension=''):
        """
        Finalize writing the file on disk, and renames it from the temp file to
        the real location.  This should be called after the data has been
        written to the temp file.

        :params fd: file descriptor of the temp file
        :param tmppath: path to the temporary file being used
        :param metadata: dictionary of metadata to be written
        :param extention: extension to be used when making the file
        """
        #Marker dir.
        if metadata[X_OBJECT_TYPE] == MARKER_DIR:
            if os.path.exists(os.path.join(self.datadir, self.obj)) and \
               not os.path.isdir(os.path.join(self.datadir, self.obj)):
                os.unlink(os.path.join(self.datadir, self.obj))
            mkdirs(os.path.join(self.datadir, self.obj))
            os.chown(os.path.join(self.datadir, self.obj), self.uid, self.gid)
            self.put_metadata(metadata)
            self.data_file = self.datadir + '/' + self.obj
            return True
        #Check if directory already exists.
        if self.is_dir:
            logging.error('Directory already exists %s/%s' % \
                          (self.datadir , self.obj))
            return False
        #metadata['name'] = self.name
        timestamp = normalize_timestamp(metadata[X_TIMESTAMP])
        write_metadata(fd, metadata)
        if X_CONTENT_LENGTH in metadata:
            self.drop_cache(fd, 0, int(metadata[X_CONTENT_LENGTH]))
        tpool.execute(os.fsync, fd)
        if self.obj_path:
            dir_objs = self.obj_path.split('/')
            tmp_path = ''
            if len(dir_objs):
                for dir_name in dir_objs:
                    if tmp_path:
                        tmp_path = tmp_path + '/' + dir_name
                    else:
                        tmp_path = dir_name
                    if not self.create_dir_object(tmp_path, metadata[X_TIMESTAMP]):
                        return False
                                       
        renamer(tmppath, os.path.join(self.datadir,
                                      self.obj + extension))
        os.chown(os.path.join(self.datadir, self.obj + extension), \
              self.uid, self.gid)
        self.metadata = metadata
        self.data_file = self.datadir + '/' + self.obj + extension
        return True
        

    def unlinkold(self, timestamp):
        """
        Remove any older versions of the object file.  Any file that has an
        older timestamp than timestamp will be deleted.

        :param timestamp: timestamp to compare with each file
        """
        timestamp = normalize_timestamp(timestamp)
        for fname in os.listdir(self.datadir):
            if fname < timestamp:
                try:
                    os.unlink(os.path.join(self.datadir, fname))
                except OSError, err:    # pragma: no cover
                    if err.errno != errno.ENOENT:
                        raise

    def unlink(self):
        """
        Remove the file.
        """
        #Marker dir.
        if self.is_dir:
            rmdirs(os.path.join(self.datadir, self.obj))
            if not os.path.isdir(os.path.join(self.datadir, self.obj)):
                self.metadata = {}
                self.data_file = None
            return
        for fname in os.listdir(self.datadir):
            if fname == self.obj:
                try:
                    os.unlink(os.path.join(self.datadir, fname))
                except OSError, err:
                    if err.errno != errno.ENOENT:
                        raise

        if self.obj_path:
            obj_dirs = self.obj_path.split('/')
            tmp_path = self.obj_path
            if len(obj_dirs):
                while tmp_path:
                    #TODO: Check dir is empty (Done in rmdirs)
                    dir_path = os.path.join(self.container_path, tmp_path)
                    metadata = read_metadata(dir_path)
                    rmdirs(dir_path)
                    if '/' in tmp_path:
                        tmp_path = tmp_path.rsplit('/', 1)[0]
                    else:
                        break
                    
        self.metadata = {}
        self.data_file = None

        
                    
    def drop_cache(self, fd, offset, length):
        """Method for no-oping buffer cache drop method."""
        if not self.keep_cache:
            drop_buffer_cache(fd, offset, length)

    def quarantine(self):
        """
        In the case that a file is corrupted, move it to a quarantined
        area to allow replication to fix it.

        :returns: if quarantine is successful, path to quarantined
                  directory otherwise None
        """
        #TODO: remove this code.
        print 'Quarantine not used'
        

    def get_data_file_size(self):
        """
        Returns the os.path.getsize for the file.  Raises an exception if this
        file does not match the Content-Length stored in the metadata. Or if
        self.data_file does not exist.

        :returns: file size as an int
        :raises DiskFileError: on file size mismatch.
        :raises DiskFileNotExist: on file not existing (including deleted)
        """
        #Marker directory.
        if self.is_dir:
            return 0
        try:
            file_size = 0
            if self.data_file:
                file_size = os.path.getsize(self.data_file)
                if  X_CONTENT_LENGTH in self.metadata:
                    metadata_size = int(self.metadata[X_CONTENT_LENGTH])
                    if file_size != metadata_size:
                        self.metadata[X_CONTENT_LENGTH] = file_size
                        self.update_object(self.metadata)
                        
                return file_size
        except OSError, err:
            if err.errno != errno.ENOENT:
                raise
        raise DiskFileNotExist('Data File does not exist.')

    def update_object(self, metadata):
        obj_path = self.datadir + '/' + self.obj
        write_metadata(obj_path, metadata)
        self.metadata = metadata


class ObjectController(object):
    """Implements the WSGI application for the Swift Object Server."""

    def __init__(self, conf):
        """
        Creates a new WSGI application for the Swift Object Server. An
        example configuration is given at
        <source-dir>/etc/object-server.conf-sample or
        /etc/swift/object-server.conf-sample.
        """
        self.logger = get_logger(conf, log_route='object-server')
        self.devices = MOUNT_PATH
        self.mount_check = conf.get('mount_check', 'true').lower() in \
                              ('true', 't', '1', 'on', 'yes', 'y')
        self.node_timeout = int(conf.get('node_timeout', 3))
        self.conn_timeout = float(conf.get('conn_timeout', 0.5))
        self.disk_chunk_size = int(conf.get('disk_chunk_size', 65536))
        self.network_chunk_size = int(conf.get('network_chunk_size', 65536))
        self.log_requests = conf.get('log_requests', 't')[:1].lower() == 't'
        self.max_upload_time = int(conf.get('max_upload_time', 86400))
        self.slow = int(conf.get('slow', 0))
        self.bytes_per_sync = int(conf.get('mb_per_sync', 512)) * 1024 * 1024
        default_allowed_headers = 'content-encoding, x-object-manifest, ' \
                                  'content-disposition'
        self.allowed_headers = set(i.strip().lower() for i in \
                conf.get('allowed_headers', \
                default_allowed_headers).split(',') if i.strip() and \
                i.strip().lower() not in DISALLOWED_HEADERS)

    def container_update(self, op, account, container, obj, headers_in,
                         headers_out, objdevice):
        """
        Update the container when objects are updated.

        :param op: operation performed (ex: 'PUT', or 'DELETE')
        :param account: account name for the object
        :param container: container name for the object
        :param obj: object name
        :param headers_in: dictionary of headers from the original request
        :param headers_out: dictionary of headers to send in the container
                            request
        :param objdevice: device name that the object is in
        """
        host = headers_in.get('X-Container-Host', None)
        partition = headers_in.get('X-Container-Partition', None)
        contdevice = headers_in.get('X-Container-Device', None)
        if not all([host, partition, contdevice]):
            return
        full_path = '/%s/%s/%s' % (account, container, obj)
        try:
            with ConnectionTimeout(self.conn_timeout):
                ip, port = host.rsplit(':', 1)
                conn = http_connect(ip, port, contdevice, partition, op,
                        full_path, headers_out)
            with Timeout(self.node_timeout):
                response = conn.getresponse()
                response.read()
                if 200 <= response.status < 300:
                    return
                else:
                    self.logger.error(_('ERROR Container update failed '
                        '(saving for async update later): %(status)d '
                        'response from %(ip)s:%(port)s/%(dev)s'),
                        {'status': response.status, 'ip': ip, 'port': port,
                         'dev': contdevice})
        except (Exception, TimeoutError):
            self.logger.exception(_('ERROR container update failed with '
                '%(ip)s:%(port)s/%(dev)s'),
                {'ip': ip, 'port': port, 'dev': contdevice})
        

    def POST(self, request):
        """Handle HTTP POST requests for the Swift Object Server."""
        try:
            device, partition, account, container, obj = \
                split_path(unquote(request.path), 5, 5, True)
        except ValueError, err:
            return HTTPBadRequest(body=str(err), request=request,
                        content_type='text/plain')
        if 'x-timestamp' not in request.headers or \
                    not check_float(request.headers['x-timestamp']):
            return HTTPBadRequest(body='Missing timestamp', request=request,
                        content_type='text/plain')
        if self.mount_check and not check_mount(self.devices, device):
            if not check_valid_account(account.replace(RESELLER_PREFIX, '', 1)):
                return Response(status='507 %s is not mounted' % device)
        file_obj = DiskFile(self.devices, device, partition, account, container,
                        obj, self.logger, disk_chunk_size=self.disk_chunk_size)

        #TODO: Handle marker dir objects.
        if not file_obj.is_valid:
            logging.error('Invalid dir obj name %s %s' % \
                              (file_obj.datadir, file_obj.obj))
            return HTTPNotFound(request=request)

        

        if file_obj.is_deleted():
            return HTTPNotFound(request=request)
        else:
            response_class = HTTPAccepted
        try:
            file_size = file_obj.get_data_file_size()
        except (DiskFileError, DiskFileNotExist):
            #TODO: What to do?
            return HTTPNotFound(request=request)
        metadata = file_obj.metadata
        metadata[X_TIMESTAMP] = request.headers['x-timestamp']
        
        metadata.update((key, value)
            for key, value in request.headers.iteritems()
            if key.lower().startswith('x-object-meta-'))
        for header_key in self.allowed_headers:
            if header_key in request.headers:
                header_caps = header_key.title()
                metadata[header_caps] = request.headers[header_key]
        
        file_obj.put_metadata(metadata)
        return response_class(request=request)

    def PUT(self, request):
        """Handle HTTP PUT requests for the Swift Object Server."""
        try:
            device, partition, account, container, obj = \
                split_path(unquote(request.path), 5, 5, True)
        except ValueError, err:
            return HTTPBadRequest(body=str(err), request=request,
                        content_type='text/plain')
        if self.mount_check and not check_mount(self.devices, device):
            if not check_valid_account(account.replace(RESELLER_PREFIX, '', 1)):
                return Response(status='507 %s is not mounted' % device)
        if 'x-timestamp' not in request.headers or \
                    not check_float(request.headers['x-timestamp']):
            return HTTPBadRequest(body='Missing timestamp', request=request,
                        content_type='text/plain')
        error_response = check_object_creation(request, obj)
        if error_response:
            return error_response
        
        file_obj = DiskFile(self.devices, device, partition, account, container,
                            obj, self.logger, disk_chunk_size=self.disk_chunk_size, \
                            uid=request.headers['uid'], gid=request.headers['gid'])
        #TODO: Handle creation of marker objs.

        if not file_obj.is_valid:
            logging.error('Invalid dir obj name %s %s' % \
                          (file_obj.datadir, file_obj.obj))
            return HTTPUnprocessableEntity(request=request)
            
        upload_expiration = time.time() + self.max_upload_time
        etag = md5()
        upload_size = 0
        last_sync = 0
        with file_obj.mkstemp() as (fd, tmppath):
            if 'content-length' in request.headers:
                fallocate(fd, int(request.headers['content-length']))
            reader = request.environ['wsgi.input'].read
            for chunk in iter(lambda: reader(self.network_chunk_size), ''):
                upload_size += len(chunk)
                if time.time() > upload_expiration:
                    return HTTPRequestTimeout(request=request)
                etag.update(chunk)
                while chunk:
                    written = os.write(fd, chunk)
                    chunk = chunk[written:]
                # For large files sync every 512MB (by default) written
                if upload_size - last_sync >= self.bytes_per_sync:
                    tpool.execute(os.fdatasync, fd)
                    drop_buffer_cache(fd, last_sync, upload_size - last_sync)
                    last_sync = upload_size

            if 'content-length' in request.headers and \
                    int(request.headers['content-length']) != upload_size:
                return Response(status='499 Client Disconnect')
            etag = etag.hexdigest()
            if 'etag' in request.headers and \
                            request.headers['etag'].lower() != etag:
                return HTTPUnprocessableEntity(request=request)

            content_type = request.headers['content-type']
            if not content_type:
                content_type = FILE_TYPE
                
            metadata = {
                X_TIMESTAMP: request.headers['x-timestamp'],
                X_CONTENT_TYPE: content_type,
                X_ETAG: etag,
                X_CONTENT_LENGTH: str(os.fstat(fd).st_size),
                X_TYPE: OBJECT,
                X_OBJECT_TYPE: FILE,
            }
            
            if request.headers['content-type'].lower() == DIR_TYPE:
                metadata.update({X_OBJECT_TYPE: MARKER_DIR})
                print 'PUT obj marker %s, type %s, size %s' % (request.path, \
                                                    request.headers['content-type'], \
                                                    request.headers['content-length'])
                                                    
            if request.headers['content-length'] == 0:
                print 'PUT obj len=0 %s, type %s, size %s' % (request.path, \
                                                    request.headers['content-type'], \
                                                    request.headers['content-length'])
                
            metadata.update(val for val in request.headers.iteritems()
                    if val[0].lower().startswith('x-object-meta-') and
                    len(val[0]) > 14)
            for header_key in self.allowed_headers:
                if header_key in request.headers:
                    header_caps = header_key.title()
                    metadata[header_caps] = request.headers[header_key]
            if not file_obj.put(fd, tmppath, metadata):
                return HTTPUnprocessableEntity(request=request)
        
        self.container_update('PUT', account, container, obj, request.headers,
            {'x-content-length': file_obj.metadata[X_CONTENT_LENGTH],
             'x-content-type': file_obj.metadata[X_CONTENT_TYPE],
             'x-timestamp': file_obj.metadata[X_TIMESTAMP],
             'x-etag': file_obj.metadata[X_ETAG],
             'x-trans-id': request.headers.get('x-trans-id', '-')},
            device)
        resp = HTTPCreated(request=request, etag=etag)
        return resp

    def GET(self, request):
        """Handle HTTP GET requests for the Swift Object Server."""
        try:
            device, partition, account, container, obj = \
                split_path(unquote(request.path), 5, 5, True)
        except ValueError, err:
            return HTTPBadRequest(body=str(err), request=request,
                        content_type='text/plain')
        if self.mount_check and not check_mount(self.devices, device):
            if not check_valid_account(account.replace(RESELLER_PREFIX, '', 1)):
                return Response(status='507 %s is not mounted' % device)
        file_obj = DiskFile(self.devices, device, partition, account, container,
                        obj, self.logger, keep_data_fp=True,
                        disk_chunk_size=self.disk_chunk_size)
        #TODO: Handle marker dir objects.
        if not file_obj.is_valid:
            logging.error('Invalid dir obj name %s %s' % \
                              (file_obj.datadir, file_obj.obj))
            return HTTPNotFound(request=request)

        
            
        if file_obj.is_deleted():
            if request.headers.get('if-match') == '*':
                return HTTPPreconditionFailed(request=request)
            else:
                return HTTPNotFound(request=request)
        try:
            file_size = file_obj.get_data_file_size()
        except (DiskFileError, DiskFileNotExist):
            #TODO: What to do?
            file_obj.close()
            return HTTPNotFound(request=request)
        if request.headers.get('if-match') not in (None, '*') and \
                file_obj.metadata[X_ETAG] not in request.if_match:
            file_obj.close()
            return HTTPPreconditionFailed(request=request)
        if request.headers.get('if-none-match') != None:
            if file_obj.metadata[X_ETAG] in request.if_none_match:
                resp = HTTPNotModified(request=request)
                resp.etag = file_obj.metadata[X_ETAG]
                file_obj.close()
                return resp
        try:
            if_unmodified_since = request.if_unmodified_since
        except (OverflowError, ValueError):
            # catches timestamps before the epoch
            file_obj.close()
            return HTTPPreconditionFailed(request=request)
        if if_unmodified_since and \
           datetime.fromtimestamp(float(file_obj.metadata[X_TIMESTAMP]), UTC) > \
           if_unmodified_since:
            file_obj.close()
            return HTTPPreconditionFailed(request=request)
        try:
            if_modified_since = request.if_modified_since
        except (OverflowError, ValueError):
            # catches timestamps before the epoch
            file_obj.close()
            return HTTPPreconditionFailed(request=request)
        if if_modified_since and \
           datetime.fromtimestamp(float(file_obj.metadata[X_TIMESTAMP]), UTC) < \
           if_modified_since:
            file_obj.close()
            return HTTPNotModified(request=request)
        if not file_obj.is_dir:
            response = Response(content_type=file_obj.metadata.get(X_CONTENT_TYPE,
                            FILE_TYPE), app_iter=file_obj,
                            request=request, conditional_response=True)
        else:
            response = Response(content_type=file_obj.metadata.get(X_CONTENT_TYPE,
                            DIR_TYPE), request=request,
                            conditional_response=True)
            
        for key, value in file_obj.metadata.iteritems():
            if key.lower().startswith('x-object-meta-') or \
                    key.lower() in self.allowed_headers:
                response.headers[key] = value
        response.etag = file_obj.metadata[X_ETAG]
        response.last_modified = float(file_obj.metadata[X_TIMESTAMP])
        response.content_length = file_size
        
        if not file_obj.is_dir and \
        response.content_length < KEEP_CACHE_SIZE and \
        'X-Auth-Token' not in request.headers and \
        'X-Storage-Token' not in request.headers:
            file_obj.keep_cache = True
            
        if 'Content-Encoding' in file_obj.metadata:
            response.content_encoding = file_obj.metadata['Content-Encoding']
        return request.get_response(response)

    def HEAD(self, request):
        """Handle HTTP HEAD requests for the Swift Object Server."""
        try:
            device, partition, account, container, obj = \
                split_path(unquote(request.path), 5, 5, True)
        except ValueError, err:
            resp = HTTPBadRequest(request=request)
            resp.content_type = 'text/plain'
            resp.body = str(err)
            return resp
        if self.mount_check and not check_mount(self.devices, device):
            if not check_valid_account(account.replace(RESELLER_PREFIX, '', 1)):
                return Response(status='507 %s is not mounted' % device)
        file_obj = DiskFile(self.devices, device, partition, account, container,
                        obj, self.logger, disk_chunk_size=self.disk_chunk_size)
        #TODO: Handle marker dir objects.
        if not file_obj.is_valid:
            logging.error('Invalid dir obj name %s %s' % \
                              (file_obj.datadir, file_obj.obj))
            return HTTPNotFound(request=request)

        
            
        if file_obj.is_deleted():
            return HTTPNotFound(request=request)
        try:
            file_size = file_obj.get_data_file_size()
        except (DiskFileError, DiskFileNotExist):
            #TODO: What to do?
            return HTTPNotFound(request=request)
        response = Response(content_type=file_obj.metadata[X_CONTENT_TYPE],
                            request=request, conditional_response=True)
        for key, value in file_obj.metadata.iteritems():
            if key.lower().startswith('x-object-meta-') or \
                    key.lower() in self.allowed_headers:
                response.headers[key] = value
        response.etag = file_obj.metadata[X_ETAG]
        response.last_modified = float(file_obj.metadata[X_TIMESTAMP])
        response.content_length = file_size
        if 'Content-Encoding' in file_obj.metadata:
            response.content_encoding = file_obj.metadata['Content-Encoding']
        return response

    def DELETE(self, request):
        """Handle HTTP DELETE requests for the Swift Object Server."""
        try:
            device, partition, account, container, obj = \
                split_path(unquote(request.path), 5, 5, True)
        except ValueError, e:
            return HTTPBadRequest(body=str(e), request=request,
                        content_type='text/plain')
        if 'x-timestamp' not in request.headers or \
                    not check_float(request.headers['x-timestamp']):
            return HTTPBadRequest(body='Missing timestamp', request=request,
                        content_type='text/plain')
        if self.mount_check and not check_mount(self.devices, device):
            if not check_valid_account(account.replace(RESELLER_PREFIX, '', 1)):
                return Response(status='507 %s is not mounted' % device)
        response_class = HTTPNoContent
        file_obj = DiskFile(self.devices, device, partition, account, container,
                        obj, self.logger, disk_chunk_size=self.disk_chunk_size)
        #TODO: Handle marker dir objects.
        if not file_obj.is_valid:
            logging.error('Invalid dir obj name %s %s' % \
                              (file_obj.datadir, file_obj.obj))
            return HTTPNotFound(request=request)
        
        
            
        if file_obj.is_deleted():
            return HTTPNotFound(request=request)
        metadata = {
             X_TIMESTAMP: request.headers['X-Timestamp'],
             X_CONTENT_LENGTH: file_obj.metadata[X_CONTENT_LENGTH],
        }
        
        file_obj.unlink()
        if not file_obj.is_deleted():
            return HTTPUnprocessableEntity(request=request)
        self.container_update('DELETE', account, container, obj,
            request.headers, {'x-timestamp': metadata[X_TIMESTAMP],
            'x-content-length': metadata[X_CONTENT_LENGTH],
            'x-trans-id': request.headers.get('x-trans-id', '-')},
            device)
        resp = response_class(request=request)
        return resp

    def REPLICATE(self, request):
        #TODO: remove this code.
        logging.error("Replicate Not used")
        

    def __call__(self, env, start_response):
        """WSGI Application entry point for the Swift Object Server."""
        start_time = time.time()
        req = Request(env)
        self.logger.txn_id = req.headers.get('x-trans-id', None)
        if not check_utf8(req.path_info):
            res = HTTPPreconditionFailed(body='Invalid UTF8')
        else:
            try:
                if hasattr(self, req.method):
                    res = getattr(self, req.method)(req)
                else:
                    res = HTTPMethodNotAllowed()
            except Exception:
                self.logger.exception(_('ERROR __call__ error with %(method)s'
                    ' %(path)s '), {'method': req.method, 'path': req.path})
                res = HTTPInternalServerError(body=traceback.format_exc())
        trans_time = time.time() - start_time
        if self.log_requests:
            log_line = '%s - - [%s] "%s %s" %s %s "%s" "%s" "%s" %.4f' % (
                req.remote_addr,
                time.strftime('%d/%b/%Y:%H:%M:%S +0000',
                              time.gmtime()),
                req.method, req.path, res.status.split()[0],
                res.content_length or '-', req.referer or '-',
                req.headers.get('x-trans-id', '-'),
                req.user_agent or '-',
                trans_time)
            if req.method == 'REPLICATE':
                self.logger.debug(log_line)
            else:
                self.logger.info(log_line)
        if req.method in ('PUT', 'DELETE'):
            slow = self.slow - trans_time
            if slow > 0:
                sleep(slow)
        return res(env, start_response)


def app_factory(global_conf, **local_conf):
    """paste.deploy app factory for creating WSGI object server apps"""
    conf = global_conf.copy()
    conf.update(local_conf)
    return ObjectController(conf)
