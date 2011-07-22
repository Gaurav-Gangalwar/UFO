rpm -Uvh http://download.fedora.redhat.com/pub/epel/5/x86_64/epel-release-5-4.noarch.rpm
yum install memcached
yum install openssl
yum install python26
yum install python26-devel
yum install python26-setuptools
easy_install-2.6 xattr netifaces eventlet greenlet paste pastedeploy configobj coverage  webob simplejson nose
mkdir -p /usr/local/gluster-object/config 2>> /dev/null
rm -rf /usr/local/gluster-object/config/*
cp gluster-object/config/* /usr/local/gluster-object/config/
cd gluster-object
python2.6 setup.py install
gluster-object-config
gluster-object-stop
gluster-object-start
cd ..
