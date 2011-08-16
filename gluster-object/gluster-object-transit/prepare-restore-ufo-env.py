#!/usr/bin/python

import os

ADMIN_URL = 'https://127.0.0.1:443/auth/'
ADMIN_KEY = '123456'

cmd = 'gluster-object-prep -K %s -A %s' %(ADMIN_KEY, ADMIN_URL)
os.system(cmd + '>>/dev/null')

fp = file("user_info", 'r+')

while True:
   user_data = fp.readline()
   cmd = 'gluster-object-add-user -a -K %s -A %s ' %(ADMIN_KEY, ADMIN_URL) +  user_data
   if len(user_data) == 0:
           break
   print cmd
   os.system(cmd + '>>/dev/null')
