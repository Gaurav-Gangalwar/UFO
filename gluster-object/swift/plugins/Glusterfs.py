import logging
import os
from ConfigParser import ConfigParser

class Glusterfs(object):

    def __init__(self):
        self.name = 'glusterfs'
        self.fs_conf = ConfigParser()
        self.fs_conf.read(os.path.join('/etc/gluster-object', 'fs.conf'))
        self.mount_path = self.fs_conf.get('DEFAULT', 'mount_path', '/mnt/gluster-object')
        
    def mount(self, mount_ip, export, mount_path):
        mnt_cmd = 'mount -t glusterfs %s:%s %s' % (mount_ip, export, \
                                                           mount_path)
        if os.system(mnt_cmd) or \
        not os.path.exists(os.path.join(mount_path)):
            logging.error('Mount failed %s: %s' % (self.name, mnt_cmd))
            return False
        
        return True

    def get_export_list(self):
        export_list = []
        cmnd = 'gluster volume info'

        if os.system(cmnd + ' >> /dev/null'):
            logging.erro('Getting volume failed %s', self.name)
            return export_list

        fp = os.popen(cmnd)
        while True:
            item = fp.readline()
            if not item:
                break
            item = item.strip(' ').strip('\n').lower()
            if item.startswith('volume name:'):
                export_list.append(item.split(':')[1].strip(' '))
            
        return export_list
