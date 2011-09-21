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

from webob import Request, Response
from webob.exc import HTTPAccepted, HTTPBadRequest, HTTPConflict, \
    HTTPCreated, HTTPForbidden, HTTPInternalServerError, \
    HTTPMethodNotAllowed, HTTPNoContent, HTTPNotFound, HTTPPreconditionFailed
import simplejson

#from swift.common.db import AccountBroker
from swift.common.utils import get_logger, get_param, hash_path, \
    normalize_timestamp, split_path, storage_directory, read_metadata, \
    write_metadata, dir_empty, mkdirs, rmdirs, check_valid_account
from swift.common.constraints import ACCOUNT_LISTING_LIMIT, \
    check_mount, check_float, check_utf8
#from swift.common.db_replicator import ReplicatorRpc
from swift.container.server import DiskDir
from swift.common.utils import X_CONTENT_TYPE, X_CONTENT_LENGTH, X_TIMESTAMP,\
     X_PUT_TIMESTAMP, X_TYPE, X_ETAG, X_OBJECTS_COUNT, X_BYTES_USED, \
     X_CONTAINER_COUNT, MOUNT_PATH, ACCOUNT, XML_EXTRA_ENTITIES
from swift import plugins


DATADIR = 'accounts'


class AccountController(object):
    """WSGI controller for the account server."""

    def __init__(self, conf):
        self.logger = get_logger(conf, log_route='account-server')
        self.fs_name = conf.get('fs_name', 'Glusterfs')
        self.fs_object = getattr(plugins, self.fs_name, False)
        if not self.fs_object:
            raise Exception('Invalid Filesystem name %s', self.fs_name)
        self.fs_object = self.fs_object()
        self.root = self.fs_object.mount_path
        self.mount_check = conf.get('mount_check', 'true').lower() in \
                              ('true', 't', '1', 'on', 'yes', 'y')
        

    def DELETE(self, req):
        """Handle HTTP DELETE request."""
        #print 'Gaurav acc_del path', req.path
        try:
            drive, part, account, container = split_path(unquote(req.path), \
                                                         3, 4)
        except ValueError, err:
            return HTTPBadRequest(body=str(err), content_type='text/plain',
                                                    request=req)
        if self.mount_check and not check_mount(self.root, drive):
            if not check_valid_account(account, self.fs_object):
                return Response(status='507 %s is not mounted' % drive)
        if 'x-timestamp' not in req.headers or \
                    not check_float(req.headers['x-timestamp']):
            return HTTPBadRequest(body='Missing timestamp', request=req,
                        content_type='text/plain')
        dir_obj = DiskDir(self.root, drive, part, account, '', self.logger)
        if not dir_obj.dir_exists:
            return HTTPNotFound()

        if container:
            #TODO: Define delete_container (Done).
            
            dir_obj.delete_container(req.headers['x-object-count'],
                                     req.headers['x-bytes-used'])
            return HTTPNoContent(request=req)
        
        if not dir_obj.empty():
            return HTTPConflict(request=req)
            
        dir_obj.delete()
        if dir_obj.dir_exists:
            return HTTPConflict(request=req)
        
        return HTTPNoContent(request=req)

    def PUT(self, req):
        """Handle HTTP PUT request."""
        try:
            drive, part, account, container = split_path(unquote(req.path),
                                                         3, 4)
            if (account and not check_utf8(account)) or \
                (container and not check_utf8(container)):
                raise ValueError('NULL characters not allowed in names')
        except ValueError, err:
            return HTTPBadRequest(body=str(err), content_type='text/plain',
                                  request=req)
        if self.mount_check and not check_mount(self.root, drive):
            if not check_valid_account(account, self.fs_object):
                return Response(status='507 %s is not mounted' % drive)

        #Account always create with default uid.
        dir_obj = DiskDir(self.root, drive, part, account, '', self.logger)
        created = not dir_obj.dir_exists
        if container:   # put account container
            if not dir_obj.dir_exists:
                return HTTPNotFound()
        
            #TODO: What is this???
            if req.headers.get('x-account-override-deleted', 'no').lower() != \
                    'yes' and not dir_obj.dir_exists:
                return HTTPNotFound(request=req)
            #TODO: define put_container
            dir_obj.put_container(req.headers['x-put-timestamp'],
                req.headers['x-object-count'],
                req.headers['x-bytes-used'])
            return HTTPCreated(request=req)
        # put account
        if not dir_obj.dir_exists:
            metadata = {X_TYPE: ACCOUNT,
                        X_TIMESTAMP: req.headers['x-timestamp'],
                        X_PUT_TIMESTAMP: req.headers['x-timestamp'],
                        X_OBJECTS_COUNT: 0,
                        X_BYTES_USED: 0,
                        X_CONTAINER_COUNT: 0}
            metadata.update((key, value)
                for key, value in req.headers.iteritems()
                if key.lower().startswith('x-account-meta-'))
                
            if metadata:
                dir_obj.put(metadata)
            
        if created:
            return HTTPCreated(request=req)
        else:
            return HTTPAccepted(request=req)

    def HEAD(self, req):
        """Handle HTTP HEAD request."""
        # TODO(refactor): The account server used to provide a 'account and
        # container existence check all-in-one' call by doing a HEAD with a
        # container path. However, container existence is now checked with the
        # container servers directly so this is no longer needed. We should
        # refactor out the container existence check here and retest
        # everything.
        try:
            drive, part, account, container = split_path(unquote(req.path),
                                                         3, 4)
        except ValueError, err:
            return HTTPBadRequest(body=str(err), content_type='text/plain',
                                                    request=req)
        if self.mount_check and not check_mount(self.root, drive):
            if not check_valid_account(account, self.fs_object):
                return Response(status='507 %s is not mounted' % drive)
        
        dir_obj = DiskDir(self.root, drive, part, account, '', self.logger)
        if not dir_obj.dir_exists:
            return HTTPNotFound(request=req)

        if 'no_count_update' not in req.headers:
            dir_obj.update_container_count()
        
        headers = {
            'X-Account-Container-Count': dir_obj.metadata[X_CONTAINER_COUNT],
            'X-Account-Object-Count': dir_obj.metadata[X_OBJECTS_COUNT],
            'X-Account-Bytes-Used': dir_obj.metadata[X_BYTES_USED],
            'X-Timestamp': dir_obj.metadata[X_TIMESTAMP],
            'X-PUT-Timestamp': dir_obj.metadata[X_PUT_TIMESTAMP]}
  
        headers.update((key, value)
            for key, value in dir_obj.metadata.iteritems()
            if value != '' and key not in headers)
        return HTTPNoContent(request=req, headers=headers)

    def GET(self, req):
        """Handle HTTP GET request."""
        try:
            drive, part, account = split_path(unquote(req.path), 3)
        except ValueError, err:
            return HTTPBadRequest(body=str(err), content_type='text/plain',
                                                    request=req)
        if self.mount_check and not check_mount(self.root, drive):
            if not check_valid_account(account, self.fs_object):
                return Response(status='507 %s is not mounted' % drive)
        dir_obj = DiskDir(self.root, drive, part, account, '', self.logger)
        if not dir_obj.dir_exists:
            return HTTPNotFound(request=req)
        
        try:
            prefix = get_param(req, 'prefix')
            delimiter = get_param(req, 'delimiter')
            if delimiter and (len(delimiter) > 1 or ord(delimiter) > 254):
                # delimiters can be made more flexible later
                return HTTPPreconditionFailed(body='Bad delimiter')
            limit = ACCOUNT_LISTING_LIMIT
            given_limit = get_param(req, 'limit')
            if given_limit and given_limit.isdigit():
                limit = int(given_limit)
                if limit > ACCOUNT_LISTING_LIMIT:
                    return  HTTPPreconditionFailed(request=req,
                        body='Maximum limit is %d' % ACCOUNT_LISTING_LIMIT)
            marker = get_param(req, 'marker', '')
            end_marker = get_param(req, 'end_marker')
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
        #print 'S3 con_type', req, out_content_type
        account_list = dir_obj.list_account_containers(limit, marker, end_marker,
                                                   prefix, delimiter)
        
        if out_content_type == 'application/json':
            json_pattern = ['"name":%s', '"count":%s', '"bytes":%s']
            json_pattern = '{' + ','.join(json_pattern) + '}'
            json_out = []
            if account_list:
                for (name, object_count, bytes_used, is_subdir) in account_list:
                    name = simplejson.dumps(name)
                    if is_subdir:
                        json_out.append('{"subdir":%s}' % name)
                    else:
                        json_out.append(json_pattern %
                            (name, object_count, bytes_used))
            account_list = '[' + ','.join(json_out) + ']'
        elif out_content_type.endswith('/xml'):
            output_list = ['<?xml version="1.1" encoding="UTF-8"?>',
                            '<account name="%s">' % account]
            if account_list:
                for (name, object_count, bytes_used, is_subdir) in account_list:
                    name = saxutils.escape(name, XML_EXTRA_ENTITIES)
                    if is_subdir:
                        output_list.append('<subdir name="%s" />' % name)
                    else:
                        item = '<container><name>%s</name><count>%s</count>' \
                                '<bytes>%s</bytes></container>' % \
                                (name, object_count, bytes_used)
                        output_list.append(item)
            output_list.append('</account>')
            account_list = '\n'.join(output_list)
        else:
            if account_list:
                account_list = '\n'.join(r[0] for r in account_list) + '\n'

        resp_headers = {
            'X-Account-Container-Count': dir_obj.metadata[X_CONTAINER_COUNT],
            'X-Account-Object-Count': dir_obj.metadata[X_OBJECTS_COUNT],
            'X-Account-Bytes-Used': dir_obj.metadata[X_BYTES_USED],
            'X-Timestamp': dir_obj.metadata[X_TIMESTAMP],
            'X-PUT-Timestamp': dir_obj.metadata[X_PUT_TIMESTAMP]}
        resp_headers.update((key, value)
            for key, value in dir_obj.metadata.iteritems()
            if value != '' and key not in resp_headers)

        if not account_list:
            return HTTPNoContent(request=req, headers=resp_headers)
        
        ret = Response(body=account_list, request=req, headers=resp_headers)
        ret.content_type = out_content_type
        #print 'S3', ret.content_type, out_content_type
        ret.charset = 'utf-8'
        return ret

    def REPLICATE(self, req):
        #TODO: remove this code.
        logging.error("Replicate Not used")
        

    def POST(self, req):
        """Handle HTTP POST request."""
        try:
            drive, part, account = split_path(unquote(req.path), 3)
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
        dir_obj = DiskDir(self.root, drive, part, account, '', self.logger)
        if not dir_obj.dir_exists:
            return HTTPNotFound(request=req)
        timestamp = normalize_timestamp(req.headers['x-timestamp'])
        metadata = dir_obj.metadata
        metadata.update((key, value)
            for key, value in req.headers.iteritems()
                if key.lower().startswith('x-account-meta-'))
        if metadata:
            dir_obj.put(metadata)
        return HTTPNoContent(request=req)
        
    def __call__(self, env, start_response):
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
        additional_info = ''
        if res.headers.get('x-container-timestamp') is not None:
            additional_info += 'x-container-timestamp: %s' % \
                res.headers['x-container-timestamp']
        log_message = '%s - - [%s] "%s %s" %s %s "%s" "%s" "%s" %s "%s"' % (
            req.remote_addr,
            time.strftime('%d/%b/%Y:%H:%M:%S +0000', time.gmtime()),
            req.method, req.path,
            res.status.split()[0], res.content_length or '-',
            req.headers.get('x-trans-id', '-'),
            req.referer or '-', req.user_agent or '-',
            trans_time,
            additional_info)
        if req.method.upper() == 'REPLICATE':
            self.logger.debug(log_message)
        else:
            self.logger.info(log_message)
        return res(env, start_response)


def app_factory(global_conf, **local_conf):
    """paste.deploy app factory for creating WSGI account server apps"""
    conf = global_conf.copy()
    conf.update(local_conf)
    return AccountController(conf)
