#!/bin/bash
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

sudo gluster-object-stop 2>> /dev/null
sudo apt-get install python-software-properties
sudo add-apt-repository ppa:swift-core/ppa
sudo apt-get update
sudo apt-get install memcached
sudo apt-get install openssl
sudo apt-get install python-configobj
sudo apt-get install python-coverage
sudo apt-get install python-dev
sudo apt-get install python-nose
sudo apt-get install python-setuptools
sudo apt-get install python-simplejson
sudo apt-get install python-xattr
sudo apt-get install python-webob
sudo apt-get install python-eventlet
sudo apt-get install python-greenlet
sudo apt-get install python-pastedeploy
sudo apt-get install python-netifaces
sudo mkdir -p /usr/local/gluster-object/config 2>> /dev/null
sudo rm -rf /usr/local/gluster-object/config/*
sudo cp gluster-object/config/* /usr/local/gluster-object/config/
cd gluster-object
sudo python setup.py install
sudo gluster-object-config
sudo gluster-object-stop
sudo gluster-object-start
cd ..
