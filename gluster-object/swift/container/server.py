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

from __future__ import with_statement

import os
import time
import traceback
from urllib import unquote
from xml.sax import saxutils
from datetime import datetime

import simplejson
from eventlet.timeout import Timeout
from eventlet import TimeoutError
from webob import Request, Response
from webob.exc import HTTPAccepted, HTTPBadRequest, HTTPConflict, \
    HTTPCreated, HTTPInternalServerError, HTTPNoContent, \
    HTTPNotFound, HTTPPreconditionFailed, HTTPMethodNotAllowed

#from swift.common.db import ContainerBroker
from swift.common.utils import get_logger, get_param, hash_path, \
    normalize_timestamp, storage_directory, split_path, read_metadata, \
    write_metadata, clean_metadata, dir_empty, mkdirs, rmdirs, validate_account, \
    validate_container, validate_object, check_valid_account, is_marker, \
    get_container_details, get_account_details, create_container_metadata, \
    create_account_metadata, create_object_metadata, cache_from_env, do_stat, \
    do_listdir
from swift.common.constraints import CONTAINER_LISTING_LIMIT, \
    check_mount, check_float, check_utf8
from swift.common.bufferedhttp import http_connect
from swift.common.exceptions import ConnectionTimeout
#from swift.common.db_replicator import ReplicatorRpc
from swift.common.utils import X_CONTENT_TYPE, X_CONTENT_LENGTH, X_TIMESTAMP,\
     X_PUT_TIMESTAMP, X_TYPE, X_ETAG, X_OBJECTS_COUNT, X_BYTES_USED, \
     X_CONTAINER_COUNT, CONTAINER, DEFAULT_UID, \
     DEFAULT_GID, XML_EXTRA_ENTITIES, TRUE_VALUES
from swift import plugins

DATADIR = 'containers'

class DiskDir(object):
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

    def __init__(self, path, device, partition, account, container, logger,
                 memcache=None, uid=DEFAULT_UID, gid=DEFAULT_GID):
        if container:
            self.name = container
        else:
            self.name = None
        if self.name:
            self.datadir = os.path.join(path, device,
                            storage_directory(DATADIR, partition, self.name))
        else:
            self.datadir = os.path.join(path, device)
        self.device_path = os.path.join(path, device)
        self.logger = logger
        self.metadata = {}
        self.uid = int(uid)
        self.gid = int(gid)
        self.memcache = memcache
        self.dir_exists = os.path.isdir (self.datadir)
        if self.dir_exists:
            self.metadata = read_metadata(self.datadir)
        else:
            return
        if container:
            if not self.metadata:
                create_container_metadata(self.datadir, memcache=self.memcache)
                self.metadata = read_metadata(self.datadir)
            ret = validate_container(self.metadata)
        else:
            if not self.metadata:
                create_account_metadata(self.datadir, memcache=self.memcache)
                self.metadata = read_metadata(self.datadir)
            ret = validate_account(self.metadata)

        if not ret:
            self.logger.error('Metadata validation failed %s %s' % \
                              (self.datadir, self.metadata))
            self.dir_exists = False
            self.metadata = {}

    def empty(self):
        return dir_empty(self.datadir)

    def delete(self):
        if self.empty():
            #For delete account.
            if os.path.ismount(self.datadir):
                clean_metadata(self.datadir)
            else:
                rmdirs(self.datadir)
            self.dir_exists = False

    def get_info(self):
        """
        Returns Object-Count and Bytes-Used.
        """

        if not os.path.isdir(self.datadir):
            return

        files = do_listdir(self.datadir)
        files_count = len(files)
        for file in files:
            dir_bytes_used += do_stat(self.datadir + '/' + file).st_size

        return files_count, dir_bytes_used


    def put_metadata(self, metadata):
        """
        Write metadata to directory/container.
        """
        write_metadata(self.datadir, metadata)
        self.metadata = metadata

    def put(self, metadata):
        """
        Create and write metatdata to directory/container.
        :param metadata: Metadata to write.
        """
        if not self.dir_exists:
            mkdirs(self.datadir)

        os.chown(self.datadir, self.uid, self.gid)
        write_metadata(self.datadir, metadata)
        self.metadata = metadata
        self.dir_exists = True

    def put_obj(self, content_length, timestamp):
        self.metadata[X_OBJECTS_COUNT] = int(self.metadata[X_OBJECTS_COUNT]) + 1
        self.metadata[X_PUT_TIMESTAMP] = timestamp
        self.metadata[X_BYTES_USED] = int(self.metadata[X_BYTES_USED]) + int(content_length)
        #TODO: define update_metadata instad of writing whole metadata again.
        self.put_metadata(self.metadata)

    def delete_obj(self, content_length):
        self.metadata[X_OBJECTS_COUNT] = int(self.metadata[X_OBJECTS_COUNT]) - 1
        self.metadata[X_BYTES_USED] = int(self.metadata[X_BYTES_USED]) - int(content_length)
        self.put_metadata(self.metadata)

    def put_container(self, timestamp, object_count, bytes_used):
        """
        For account server.
        """
        self.metadata[X_OBJECTS_COUNT] = 0
        self.metadata[X_BYTES_USED] = 0
        self.metadata[X_CONTAINER_COUNT] = int(self.metadata[X_CONTAINER_COUNT]) + 1
        self.metadata[X_PUT_TIMESTAMP] = timestamp
        self.put_metadata(self.metadata)

    def delete_container(self, object_count, bytes_used):
        """
        For account server.
        """
        self.metadata[X_OBJECTS_COUNT] = 0
        self.metadata[X_BYTES_USED] = 0
        self.metadata[X_CONTAINER_COUNT] = int(self.metadata[X_CONTAINER_COUNT]) - 1
        self.put_metadata(self.metadata)

    def unlink(self):
        """
        Remove directory/container if empty.
        """
        if dir_empty(self.datadir):
            rmdirs(self.datadir)

    def filter_prefix(self, objects, prefix):
        """
        Accept sorted list.
        """
        found = 0
        filtered_objs = []
        for object_name in objects:
            if object_name.startswith(prefix):
                filtered_objs.append(object_name)
                found = 1
            else:
                if found:
                    break

        return filtered_objs

    def filter_delimiter(self, objects, delimiter, prefix):
        """
        Accept sorted list.
        Objects should start with prefix.
        """
        filtered_objs=[]
        for object_name in objects:
            tmp_obj = object_name.replace(prefix, '', 1)
            sufix = tmp_obj.split(delimiter, 1)
            new_obj = prefix + sufix[0]
            if new_obj and new_obj not in filtered_objs:
                filtered_objs.append(new_obj)

        return filtered_objs

    def filter_marker(self, objects, marker):
        """
        TODO: We can traverse in reverse order to optimize.
        Accept sorted list.
        """
        filtered_objs=[]
        found = 0
        if objects[-1] < marker:
            return filtered_objs
        for object_name in objects:
            if object_name > marker:
                filtered_objs.append(object_name)

        return filtered_objs

    def filter_end_marker(self, objects, end_marker):
        """
        Accept sorted list.
        """
        filtered_objs=[]
        for object_name in objects:
            if object_name < end_marker:
                filtered_objs.append(object_name)
            else:
                break

        return filtered_objs

    def filter_limit(self, objects, limit):
        filtered_objs=[]
        for i in range(0, limit):
            filtered_objs.append(objects[i])

        return filtered_objs

    def list_container_objects(self, limit, marker, end_marker,
                               prefix, delimiter, path, out_content_type):
        """
        Returns tuple of name, created_at, size, content_type, etag.
        """
        if path:
            prefix = path = path.rstrip('/') + '/'
            delimiter = '/'
        if delimiter and not prefix:
            prefix = ''

        #print 'Container_list prefix, del, datadir', prefix,\
                                                   #delimiter, self.datadir

        objects = []
        object_count = 0
        bytes_used = 0
        container_list = []

        objects, object_count, bytes_used = get_container_details(self.datadir,
                                                                  self.memcache)

        #print 'cont', object_count, self.metadata

        if int(self.metadata[X_OBJECTS_COUNT]) != object_count or \
           int(self.metadata[X_BYTES_USED]) != bytes_used:
            self.metadata[X_OBJECTS_COUNT] = object_count
            self.metadata[X_BYTES_USED] = bytes_used
            self.update_container(self.metadata)

        if objects:
            objects.sort()

        if objects and prefix:
            objects = self.filter_prefix(objects, prefix)

        if objects and delimiter:
            objects = self.filter_delimiter(objects, delimiter, prefix)

        if objects and marker:
            objects = self.filter_marker(objects, marker)

        if objects and end_marker:
            objects = self.filter_end_marker(objects, end_marker)

        if objects and limit:
            if len(objects) > limit:
                objects = self.filter_limit(objects, limit)

        if objects:
            for obj in objects:
                list_item = []
                metadata = None
                list_item.append(obj)
                if out_content_type != 'text/plain':
                    metadata = read_metadata(self.datadir + '/' + obj)
                    if not metadata:
                        metadata = create_object_metadata(self.datadir + '/' + obj)
                #print 'Gaurav list_obj meta', metadata
                if metadata:
                    list_item.append(metadata[X_TIMESTAMP])
                    list_item.append(metadata[X_CONTENT_LENGTH])
                    list_item.append(metadata[X_CONTENT_TYPE])
                    list_item.append(metadata[X_ETAG])
                container_list.append(list_item)

        #print 'Gaurav list_container objs', container_list
        return container_list

    def list_account_containers(self, limit, marker, end_marker,
                                                   prefix, delimiter,
                                                   out_content_type):
        """
        Return tuple of name, object_count, bytes_used, 0(is_subdir).
        Used by account server.
        """
        if delimiter and not prefix:
            prefix = ''
        containers = []
        container_count = 0
        account_list = []

        containers, container_count = get_account_details(self.datadir, self.memcache)

        if int(self.metadata[X_CONTAINER_COUNT]) != container_count:
            self.metadata[X_CONTAINER_COUNT] = container_count
            self.update_account(self.metadata)

        if containers:
            containers.sort()

        if containers and prefix:
            containers = self.filter_prefix(containers, prefix)

        if containers and delimiter:
            containers = self.filter_delimiter(containers, delimiter, prefix)

        if containers and marker:
            containers = self.filter_marker(containers, marker)

        if containers and end_marker:
            containers = self.filter_end_marker(containers, end_marker)

        if containers and limit:
            if len(containers) > limit:
                containers = self.filter_limit(containers, limit)

        if containers:
            for cont in containers:
                list_item = []
                metadata = None
                list_item.append(cont)
                if out_content_type != 'text/plain':
                    metadata = read_metadata(self.datadir + '/' + cont)
                    if not metadata:
                        metadata = create_container_metadata(self.datadir + '/' + cont)

                if metadata:
                    list_item.append(metadata[X_OBJECTS_COUNT])
                    list_item.append(metadata[X_BYTES_USED])
                    list_item.append(0)
                account_list.append(list_item)

        #print 'Gaurav list_containet objs', objects
        return account_list

    def update_container(self, metadata):
        cont_path = self.datadir
        write_metadata(cont_path, metadata)
        self.metadata = metadata

    def update_account(self, metadata):
        acc_path = self.datadir
        write_metadata(acc_path, metadata)
        self.metadata = metadata

    def update_object_count(self):
        objects = []
        object_count = 0
        bytes_used = 0
        objects, object_count, bytes_used = get_container_details(self.datadir,
                                                                  self.memcache)

        #print 'cont', object_count, self.metadata

        if int(self.metadata[X_OBJECTS_COUNT]) != object_count or \
           int(self.metadata[X_BYTES_USED]) != bytes_used:
            self.metadata[X_OBJECTS_COUNT] = object_count
            self.metadata[X_BYTES_USED] = bytes_used
            self.update_container(self.metadata)

    def update_container_count(self):
        containers = []
        container_count = 0

        containers, container_count = get_account_details(self.datadir, self.memcache)

        if int(self.metadata[X_CONTAINER_COUNT]) != container_count:
            self.metadata[X_CONTAINER_COUNT] = container_count
            self.update_account(self.metadata)


class ContainerController(object):
    """WSGI Controller for the container server."""

    # Ensure these are all lowercase
    #We don't support 'x-container-sync-key' and 'x-container-sync-to'.
    save_headers = ['x-container-read', 'x-container-write']

    def __init__(self, conf):
        self.logger = get_logger(conf, log_route='container-server')
        self.fs_name = conf.get('fs_name', 'Glusterfs')
        self.enable_caching = conf.get('enable_caching', 'False') in TRUE_VALUES
        self.fs_object = getattr(plugins, self.fs_name, False)
        if not self.fs_object:
            raise Exception('Invalid Filesystem name %s', self.fs_name)
        self.fs_object = self.fs_object()
        self.root = self.fs_object.mount_path
        self.mount_check = conf.get('mount_check', 'true').lower() in \
                              ('true', 't', '1', 'on', 'yes', 'y')
        self.node_timeout = int(conf.get('node_timeout', 3))
        self.conn_timeout = float(conf.get('conn_timeout', 0.5))
        #self.replicator_rpc = ReplicatorRpc(self.root, DATADIR,
                                            #ContainerBroker, self.mount_check)


    def account_update(self, req, account, container, dir_obj):
        """
        Update the account server with latest container info.

        :param req: webob.Request object
        :param account: account name
        :param container: container name
        :param borker: container DB broker object
        :returns: if the account request returns a 404 error code,
                  HTTPNotFound response object, otherwise None.
        """
        account_host = req.headers.get('X-Account-Host')
        account_partition = req.headers.get('X-Account-Partition')
        account_device = req.headers.get('X-Account-Device')
        if all([account_host, account_partition, account_device]):
            account_ip, account_port = account_host.rsplit(':', 1)
            new_path = '/' + '/'.join([account, container])
            account_headers = {'x-put-timestamp': dir_obj.metadata[X_PUT_TIMESTAMP],
                'x-timestamp': dir_obj.metadata[X_TIMESTAMP],
                'x-object-count': dir_obj.metadata[X_OBJECTS_COUNT],
                'x-bytes-used': dir_obj.metadata[X_BYTES_USED],
                'x-trans-id': req.headers.get('x-trans-id', '-')}
            if req.headers.get('x-account-override-deleted', 'no').lower() == \
                    'yes':
                account_headers['x-account-override-deleted'] = 'yes'
            try:
                with ConnectionTimeout(self.conn_timeout):
                    conn = http_connect(account_ip, account_port,
                        account_device, account_partition, req.method , new_path,
                        account_headers)
                with Timeout(self.node_timeout):
                    account_response = conn.getresponse()
                    account_response.read()
                    if account_response.status == 404:
                        return HTTPNotFound(request=req)
                    elif account_response.status < 200 or \
                            account_response.status > 299:
                        self.logger.error(_('ERROR Account update failed '
                            'with %(ip)s:%(port)s/%(device)s (will retry '
                            'later): Response %(status)s %(reason)s'),
                            {'ip': account_ip, 'port': account_port,
                             'device': account_device,
                             'status': account_response.status,
                             'reason': account_response.reason})
            except (Exception, TimeoutError):
                self.logger.exception(_('ERROR account update failed with '
                    '%(ip)s:%(port)s/%(device)s (will retry later)'),
                    {'ip': account_ip, 'port': account_port,
                     'device': account_device})
        return None

    def DELETE(self, req):
        """Handle HTTP DELETE request."""
        try:
            drive, part, account, container, obj = split_path(
                unquote(req.path), 4, 5, True)
        except ValueError, err:
            return HTTPBadRequest(body=str(err), content_type='text/plain',
                                request=req)
        if 'x-timestamp' not in req.headers or \
                    not check_float(req.headers['x-timestamp']):
            return HTTPBadRequest(body='Missing timestamp', request=req,
                        content_type='text/plain')
        if self.mount_check and not check_mount(self.root, drive):
            if not check_valid_account(account, self.fs_object):
                return Response(status='507 %s is not mounted' % drive)
        #broker = self._get_container_broker(drive, part, account, container)
        dir_obj = DiskDir(self.root, drive, part, account, container,
                          self.logger, memcache = self.memcache)
        existed = dir_obj.dir_exists
        if not dir_obj.dir_exists:
            return HTTPNotFound()
        if obj:     # delete object
            dir_obj.delete_obj(req.headers.get('x-content-length'))
            return HTTPNoContent(request=req)
        else:
            # delete container
            if not dir_obj.empty():
                return HTTPConflict(request=req)
            #existed = float(broker.get_info()['put_timestamp']) and \
                      #not broker.is_deleted()
            dir_obj.delete()
            if dir_obj.dir_exists:
                return HTTPConflict(request=req)
            resp = self.account_update(req, account, container, dir_obj)
            if resp:
                return resp
            if existed:
                return HTTPNoContent(request=req)
            return HTTPNotFound()

    def PUT(self, req):
        """Handle HTTP PUT request."""
        try:
            drive, part, account, container, obj = split_path(
                unquote(req.path), 4, 5, True)
            if (account and not check_utf8(account)) or \
                (container and not check_utf8(container)) or \
                (obj and not check_utf8(obj)):
                raise ValueError('NULL characters not allowed in names')
        except ValueError, err:
            return HTTPBadRequest(body=str(err), content_type='text/plain',
                                request=req)
        if 'x-timestamp' not in req.headers or \
                    not check_float(req.headers['x-timestamp']):
            return HTTPBadRequest(body='Missing timestamp', request=req,
                        content_type='text/plain')
        if self.mount_check and not check_mount(self.root, drive):
            if not check_valid_account(account, self.fs_object):
                return Response(status='507 %s is not mounted' % drive)
        timestamp = normalize_timestamp(req.headers['x-timestamp'])
        #TODO: Store this timestamp as created time if container doesn't exists.
        if not obj:
            dir_obj = DiskDir(self.root, drive, part, account, container, self.logger, \
                              memcache = self.memcache, uid = req.headers['uid'],
                              gid = req.headers['gid'])
        else:
            dir_obj = DiskDir(self.root, drive, part, account, container,
                              self.logger, memcache = self.memcache)

        created = not dir_obj.dir_exists
        if obj: #put object in container
            if dir_obj.dir_exists:
                dir_obj.put_obj(int(req.headers['x-content-length']),
                                req.headers['x-timestamp'])
                return HTTPCreated(request=req)
            else:
                return HTTPNotFound()
        #create container.
        if not dir_obj.dir_exists:
            metadata = {X_TYPE: CONTAINER,
                        X_TIMESTAMP: req.headers['x-timestamp'],
                        X_PUT_TIMESTAMP: req.headers['x-timestamp'],
                        X_OBJECTS_COUNT: 0,
                        X_BYTES_USED: 0}
            metadata.update((key, value)
                for key, value in req.headers.iteritems()
                if key.lower() in self.save_headers or
                   key.lower().startswith('x-container-meta-'))

            #print 'Gaurav Container PUT meta', metadata

            if metadata:
                dir_obj.put(metadata)

            if created:
                resp = self.account_update(req, account, container, dir_obj)
                if resp:
                    return resp
        if created:
            return HTTPCreated(request=req)
        else:
            return HTTPAccepted(request=req)

    def HEAD(self, req):
        """Handle HTTP HEAD request."""
        try:
            drive, part, account, container, obj = split_path(
                unquote(req.path), 4, 5, True)
        except ValueError, err:
            return HTTPBadRequest(body=str(err), content_type='text/plain',
                                request=req)
        if self.mount_check and not check_mount(self.root, drive):
            if not check_valid_account(account, self.fs_object):
                return Response(status='507 %s is not mounted' % drive)

        dir_obj = DiskDir(self.root, drive, part, account, container,
                          self.logger, memcache = self.memcache)
        if not dir_obj.dir_exists:
            return HTTPNotFound(request=req)

        if 'no_count_update' not in req.headers:
            dir_obj.update_object_count()

        headers = {
            'X-Container-Object-Count': dir_obj.metadata[X_OBJECTS_COUNT],
            'X-Container-Bytes-Used': dir_obj.metadata[X_BYTES_USED],
            'X-Timestamp': dir_obj.metadata[X_TIMESTAMP],
            'X-PUT-Timestamp': dir_obj.metadata[X_PUT_TIMESTAMP],
        }
        headers.update((key, value)
            for key, value in dir_obj.metadata.iteritems()
            if value != '' and key not in headers)
        #print 'Gaurav Container_Head headers', headers
        return HTTPNoContent(request=req, headers=headers)

    def GET(self, req):
        """Handle HTTP GET request."""
        try:
            drive, part, account, container, obj = split_path(
                unquote(req.path), 4, 5, True)
        except ValueError, err:
            return HTTPBadRequest(body=str(err), content_type='text/plain',
                                request=req)
        if self.mount_check and not check_mount(self.root, drive):
            if not check_valid_account(account, self.fs_object):
                return Response(status='507 %s is not mounted' % drive)

        dir_obj = DiskDir(self.root, drive, part, account, container,
                          self.logger, memcache = self.memcache)
        if not dir_obj.dir_exists:
            return HTTPNotFound(request=req)

        try:
            path = get_param(req, 'path')
            prefix = get_param(req, 'prefix')
            delimiter = get_param(req, 'delimiter')
            #print 'Gaurav Obj_Get path, prefix, del', path, prefix, delimiter
            if delimiter and (len(delimiter) > 1 or ord(delimiter) > 254):
                # delimiters can be made more flexible later
                return HTTPPreconditionFailed(body='Bad delimiter')
            marker = get_param(req, 'marker', '')
            end_marker = get_param(req, 'end_marker')
            limit = CONTAINER_LISTING_LIMIT
            given_limit = get_param(req, 'limit')
            if given_limit and given_limit.isdigit():
                limit = int(given_limit)
                if limit > CONTAINER_LISTING_LIMIT:
                    return HTTPPreconditionFailed(request=req,
                        body='Maximum limit is %d' % CONTAINER_LISTING_LIMIT)
            query_format = get_param(req, 'format')
        except (UnicodeDecodeError, ValueError), err:
            return HTTPBadRequest(body='parameters not utf8 or contain NULLs',
                                  content_type='text/plain', request=req)
        if query_format:
            req.accept = 'application/%s' % query_format.lower()
        out_content_type = req.accept.best_match(
                                ['text/plain', 'application/json',
                                 'application/xml', 'text/xml'],
                                default_match='text/plain')
        container_list = dir_obj.list_container_objects(limit, marker, end_marker,
                                                  prefix, delimiter, path,
                                                  out_content_type)
        
        if out_content_type == 'application/json':
            json_pattern = ['"name":%s', '"hash":"%s"', '"bytes":%s',
                            '"content_type":%s, "last_modified":"%s"']
            json_pattern = '{' + ','.join(json_pattern) + '}'
            json_out = []
            if container_list:
                for (name, created_at, size, content_type, etag) in container_list:
                    # escape name and format date here
                    name = simplejson.dumps(name)
                    created_at = datetime.utcfromtimestamp(
                        float(created_at)).isoformat()
                    if content_type is None:
                        json_out.append('{"subdir":%s}' % name)
                    else:
                        content_type = simplejson.dumps(content_type)
                        json_out.append(json_pattern % (name,
                                                        etag,
                                                        size,
                                                        content_type,
                                                        created_at))
            container_list = '[' + ','.join(json_out) + ']'
        elif out_content_type.endswith('/xml'):
            xml_output = []
            if container_list:
                for (name, created_at, size, content_type, etag) in container_list:
                    # escape name and format date here
                    name = saxutils.escape(name, XML_EXTRA_ENTITIES)
                    created_at = datetime.utcfromtimestamp(
                        float(created_at)).isoformat()
                    if content_type is None:
                        xml_output.append('<subdir name="%s"><name>%s</name>'
                                            '</subdir>' % (name, name))
                    else:
                        content_type = saxutils.escape(content_type,
                                                        XML_EXTRA_ENTITIES)
                        xml_output.append('<object><name>%s</name><hash>%s</hash>'\
                                '<bytes>%d</bytes><content_type>%s</content_type>'\
                                '<last_modified>%s</last_modified></object>' % \
                                (name, etag, int(size), content_type, created_at))
            container_list = ''.join([
                '<?xml version="1.1" encoding="UTF-8"?>\n',
                '<container name=%s>' % 
                saxutils.quoteattr(container, XML_EXTRA_ENTITIES),
                ''.join(xml_output), '</container>'])
        else:
            if container_list:
                container_list = '\n'.join(r[0] for r in container_list) + '\n'

        resp_headers = {
            'X-Container-Object-Count': dir_obj.metadata[X_OBJECTS_COUNT],
            'X-Container-Bytes-Used': dir_obj.metadata[X_BYTES_USED],
            'X-Timestamp': dir_obj.metadata[X_TIMESTAMP],
            'X-PUT-Timestamp': dir_obj.metadata[X_PUT_TIMESTAMP],
        }
        resp_headers.update((key, value)
            for key, value in dir_obj.metadata.iteritems()
            if value != '' and key not in resp_headers)

        if not container_list:
            return HTTPNoContent(request=req, headers=resp_headers)

        ret = Response(body=container_list, request=req, headers=resp_headers)
        ret.content_type = out_content_type
        ret.charset = 'utf-8'
        return ret

    def REPLICATE(self, req):
        #TODO: remove this code.
        logging.error("Replicate Not used")


    def POST(self, req):
        """Handle HTTP POST request."""
        try:
            drive, part, account, container = split_path(unquote(req.path), 4)
        except ValueError, err:
            return HTTPBadRequest(body=str(err), content_type='text/plain',
                                  request=req)
        if 'x-timestamp' not in req.headers or \
                not check_float(req.headers['x-timestamp']):
            return HTTPBadRequest(body='Missing or bad timestamp',
                request=req, content_type='text/plain')
        if self.mount_check and not check_mount(self.root, drive):
            if not check_valid_account(account, self.fs_object):
                return Response(status='507 %s is not mounted' % drive)
        dir_obj = DiskDir(self.root, drive, part, account, container,
                          self.logger, memcache = self.memcache)
        if not dir_obj.dir_exists:
            return HTTPNotFound(request=req)
        timestamp = normalize_timestamp(req.headers['x-timestamp'])
        metadata = dir_obj.metadata
        metadata.update((key, value)
            for key, value in req.headers.iteritems()
            if key.lower() in self.save_headers or
               key.lower().startswith('x-container-meta-'))
        #print 'Gaurav Container POST meta', metadata
        if metadata:
            dir_obj.put_metadata(metadata)
        return HTTPNoContent(request=req)

    def __call__(self, env, start_response):
        if self.enable_caching:
            self.memcache = cache_from_env(env)
        else:
            self.memcache = None
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
        trans_time = '%.4f' % (time.time() - start_time)
        log_message = '%s - - [%s] "%s %s" %s %s "%s" "%s" "%s" %s' % (
            req.remote_addr,
            time.strftime('%d/%b/%Y:%H:%M:%S +0000',
                          time.gmtime()),
            req.method, req.path,
            res.status.split()[0], res.content_length or '-',
            req.headers.get('x-trans-id', '-'),
            req.referer or '-', req.user_agent or '-',
            trans_time)
        if req.method.upper() == 'REPLICATE':
            self.logger.debug(log_message)
        else:
            self.logger.info(log_message)
        return res(env, start_response)


def app_factory(global_conf, **local_conf):
    """paste.deploy app factory for creating WSGI container server apps"""
    conf = global_conf.copy()
    conf.update(local_conf)
    return ContainerController(conf)
