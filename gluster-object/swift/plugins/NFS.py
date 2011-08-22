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

import logging
import os
from ConfigParser import ConfigParser
from swift.common.utils import get_account_id
from hashlib import md5

class NFS(object):

    def __init__(self):
        self.name = 'nfs'
        self.fs_conf = ConfigParser()
        self.fs_conf.read(os.path.join('/etc/gluster-object', 'fs.conf'))
        self.mount_path = self.fs_conf.get('DEFAULT', 'mount_path', '/mnt/nfs-object')
        self.auth_account = self.fs_conf.get('DEFAULT', 'auth_account', 'auth')

    def mount(self, mount_ip, account, mount_path):
        export = self.get_export_from_account_id(account)
        mnt_cmd = 'mount -t nfs %s:%s %s' % (mount_ip, export, \
                                                           mount_path)
        if os.system(mnt_cmd) or \
        not os.path.exists(os.path.join(mount_path)):
            raise Exception('Mount failed %s: %s' % (self.name, mnt_cmd))
            return False
        
        return True

    def unmount(self, mount_path):
        umnt_cmd = 'umount %s 2>> /dev/null' % mount_path
        if os.system(umnt_cmd):
            logging.error('Unable to unmount %s %s' % (mount_path, self.name))

        
    def get_export_list(self):
        export_list = []
        cmnd = 'showmount -e'

        if os.system(cmnd + ' >> /dev/null'):
            logging.error('Getting volume failed %s', self.name)
            return export_list

        fp = os.popen(cmnd)
        while True:
            item = fp.readline()
            if not item:
                break
            item = item.strip('\n').strip('*').strip(' ')
            export_list.append(item)
            
        return export_list

    def get_export_from_account_id(self, account):
        for export in self.get_export_list():
            if account == get_account_id(export):
                return export

        raise Exception('No export found %s %s' % (account, self.name))
        return None
