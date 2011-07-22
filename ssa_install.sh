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
