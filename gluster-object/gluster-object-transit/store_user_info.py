#!/usr/bin/python

import os, ast

AUTH_ACCOUNT = '/mnt/swift/auth'

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

    return acc_list

def get_user_data(acc, user):
    fp = file(os.path.join(AUTH_ACCOUNT, acc, user))
    user_dt = fp.readline()
    print acc + ':' + user + '=' + user_dt
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
                    info = ' '.join([acc, user,
                                    user_data['auth'].replace('plaintext:', ''),
                                    user_data['uid'], user_data['gid']])
                    print info
                    fpi.writelines(info + '\n')
    fpi.close()
store_user_info()
