#!/bin/bash

### Instal EPEL  
rpm -i https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
dnf config-manager --set-enabled ol8_codeready_builder

### Install base packages
dnf install -y `cat /feta-repo/dependencies/yum-packages`


### Install NEMEA
wget -O /etc/yum.repos.d/copr-cesnet-ipfix.repo https://copr.fedorainfracloud.org/coprs/g/CESNET/IPFIXcol/repo/epel-8/group_CESNET-IPFIXcol-epel-8.repo
rpm --import https://copr-be.cloud.fedoraproject.org/results/@CESNET/IPFIXcol/pubkey.gpg
wget -O /etc/yum.repos.d/cesnet-nemea.repo https://copr.fedorainfracloud.org/coprs/g/CESNET/NEMEA/repo/epel-8/group_CESNET-NEMEA-epel-8.repo
rpm --import https://copr-be.cloud.fedoraproject.org/results/@CESNET/NEMEA/pubkey.gpg
dnf install -y nemea-framework ipfixcol2 ipfixcol2-unirec-output ipfixprobe nemea-modules
dnf install -y cesnet-ipfix-elements

cp /opt/ipfixcol2/unirec-elements.txt /etc/ipfixcol2/
cp /opt/ipfixcol2/unirec-startup.xml.example /etc/ipfixcol2/unirec-startup.xml
cp /opt/libfds/system/elements/* /etc/libfds/system/elements/


chmod 644 /etc/ipfixcol2/unirec-startup.xml
chmod 644 /etc/ipfixcol2/unirec-elements.txt
chmod 644 /etc/libfds/system/elements/cesnet.xml

mkdir -p /var/run/libtrap/
chmod 777 /var/run/libtrap/

### Install Python dependencies
pip3.9 install -r /feta-repo/dependencies/python-requirements.txt