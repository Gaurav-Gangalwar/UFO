#########################################################################
# Command to build rpms.                                                #
#   $ rpmbuild -bb --buildroot=/home/makerpm/build/ROOT/ ufo.spec       #
#########################################################################
# Setting up the environment.                                           #
#   * sh centos_install.sh                                              #
#   * yum groupinstall "Development Tools"                              #
#   * yum install rpmdevtools                                           #
#   * rpmdev-setuptree                                                  #
# For more information refer                                            #
#   http://fedoraproject.org/wiki/How_to_create_an_RPM_package          #
#########################################################################

%define _localdir /usr/local/
%define _usrdir /usr/
%define _objdir gluster-object
%define _libdir /usr/lib/

%define _ufo_version 1.0
%define _ufo_release beta

Summary: GlusterFS Unified File and Object Storage.
Name: glusterfs
Version: %{_ufo_version}
Release: %{_ufo_release}
Group: Application/File
Vendor: Gluster Inc.
Packager: gluster-users@gluster.org
License: Apache
BuildArch: noarch

%description
Gluster’s Unified File and Object Storage unifies NAS and object storage
technology. This provides a system for data storage that enables users to access
the same data as an object and as a file, simplifying management and controlling
storage costs.

%package ufo
Summary: Glusterfs UFO
Group: Application/File
Requires: memcached
Requires: openssl
Requires: python

%description ufo
Gluster’s Unified File and Object Storage unifies NAS and object storage
technology. This provides a system for data storage that enables users to access
the same data as an object and as a file, simplifying management and controlling
storage costs.

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/%{_libdir}/python2.6/site-packages
mkdir -p %{buildroot}/%{_localdir}/%{_objdir}/config
mkdir -p %{buildroot}/%{_bindir}

cp -r %{_libdir}/python2.6/site-packages/*.egg %{buildroot}/%{_libdir}/python2.6/site-packages
cp -r %{_localdir}/%{_objdir}/config/* %{buildroot}/%{_localdir}/%{_objdir}/config
cp -rv %{_bindir}/gluster-object-* %{buildroot}/%{_bindir}

%pre ufo
mkdir -p %{_libdir}/python2.6/site-packages
mkdir -p %{_localdir}/%{_objdir}/config
mkdir -p %{_conf_dir}/gluster-object

%files ufo
%defattr(-,root,root)
%{_libdir}/python2.6/site-packages
%{_localdir}/%{_objdir}/config
%{_bindir}/*

%clean
rm -rf %{buildroot}
