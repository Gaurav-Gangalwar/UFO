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

gluster-object-stop 2>> /dev/null
rpm -Uvh http://download.fedora.redhat.com/pub/epel/5/x86_64/epel-release-5-4.noarch.rpm
yum install memcached
yum install openssl
yum install python26
yum install python26-devel
rm -rf /usr/lib/python2.6/site-packages/* >> /dev/null
cp -r usr/lib/python2.6/site-packages/* /usr/lib/python2.6/site-packages/ >> /dev/null
mkdir -p /usr/local/gluster-object/config 2>> /dev/null
rm -rf /usr/local/gluster-object/config/*
cp gluster-object/config/* /usr/local/gluster-object/config/
cd gluster-object
python2.6 setup.py install
gluster-object-config
gluster-object-stop
gluster-object-start
cd ..
rpm -ev epel-release-5-4.noarch
