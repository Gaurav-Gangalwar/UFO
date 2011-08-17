#!/usr/bin/python

import os, ast
from tempfile import mkdtemp

AUTH_ACCOUNT = ''
ADMIN_URL = ''
ADMIN_KEY = ''

def restore_user_data():
    cmd = 'gluster-object-prep -K %s -A %s' %(ADMIN_KEY, ADMIN_URL)
    os.system(cmd + '>>/dev/null')

    fp = file("user_info", 'r+')

    while True:
       user_data = fp.readline()
       cmd = 'gluster-object-add-user -K %s -A %s %s' %(ADMIN_KEY, ADMIN_URL,
                                                         user_data)
       if len(user_data) == 0:
               break
       print cmd
       os.system(cmd + '>>/dev/null')
    fp.close()


def get_account_list():
    acc_list = []
    cmnd = 'gluster volume info'

    if os.system(cmnd + ' >> /dev/null'):
        raise Exception('Getting volume info failed')
        return acc_list

    fp = os.popen(cmnd)
    while True:
        item = fp.readline()
        if not item:
            break
        item = item.strip('\n').strip(' ')
        if item.lower().startswith('volume name:'):
            acc_list.append(item.split(':')[1].strip(' '))

    fp.close()

    return acc_list


def get_user_data(acc, user):
    fp = file(os.path.join(AUTH_ACCOUNT, acc, user))
    user_dt = fp.readline()
    print acc + ':' + user + '=' + user_dt
    fp.close()
    return ast.literal_eval(user_dt)


def store_user_info():
    fpi = file('user_info', 'w+')
    accounts = get_account_list()
    for acc in accounts:
        if os.path.isdir(os.path.join(AUTH_ACCOUNT, acc)):
            for user in os.listdir(os.path.join(AUTH_ACCOUNT, acc)):
                if user != '.services':
                    user_data = {}
                    user_data = get_user_data(acc, user)
                    user_details = ''
                    for dict in user_data['groups']:
                        if dict['name'] == '.admin':
                            user_details += '-a '
                        if dict['name'] == '.reseller_admin':
                            user_details += '-r '
                    user_details = user_details + ' '.join([acc, user,
                                    user_data['auth'].replace('plaintext:', ''),
                                    user_data['uid'], user_data['gid']])
                    fpi.writelines(user_details + '\n')
    fpi.close()


def clear_existing_data()
    cmd = 'rm -rf ' + AUTH_ACCOUNT
    os.system(cmd + '2>/dev/null')


def unmount_tmp_dir()
    mnt_cmd = 'umount ' + AUTH_ACCOUNT

    if os.system(mnt_cmd)
        raise Exception('Unount failed on %s' % (AUTH_ACCOUNT))

    os.rmdir(AUTH_ACCOUNT)


def init():
    global AUTH_ACCOUNT
    global ADMIN_URL
    global ADMIN_KEY

    ADMIN_URL = raw_input('Enter the ADMIN_URL:')
    ADMIN_KEY = raw_input('Enter the ADMIN_KEY:')
    AUTH_ACCOUNT = mkdtemp(dir='/tmp')

    mnt_cmd = 'mount -t glusterfs localhost:/auth %s' %AUTH_ACCOUNT
    if os.system(mnt_cmd)
        raise Exception('Mount failed on %s' % (AUTH_ACCOUNT))
        exit(1)


def main():
    init()
    store_user_info()
    clear_existing_data()
    restore_user_data()
    unmount_tmp_dir()


if __name__ == '__main__':
    main()
