#!/bin/bash

### Export variables
export shared_path="/feta-repo"
export VAGRANT_HOME="/home/vagrant"

### Instal EPEL  
rpm -i https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
dnf config-manager --set-enabled ol8_codeready_builder


### Install NEMEA
wget -O /etc/yum.repos.d/copr-cesnet-ipfix.repo https://copr.fedorainfracloud.org/coprs/g/CESNET/IPFIXcol/repo/epel-8/group_CESNET-IPFIXcol-epel-8.repo
rpm --import https://copr-be.cloud.fedoraproject.org/results/@CESNET/IPFIXcol/pubkey.gpg
wget -O /etc/yum.repos.d/cesnet-nemea.repo https://copr.fedorainfracloud.org/coprs/g/CESNET/NEMEA/repo/epel-8/group_CESNET-NEMEA-epel-8.repo
rpm --import https://copr-be.cloud.fedoraproject.org/results/@CESNET/NEMEA/pubkey.gpg

### Install base packages

cd $shared_path/global_dependencies
dnf install -y `cat yum-packages`


mkdir -p /var/run/libtrap/
chmod 777 /var/run/libtrap/

echo 'export shared_path="/feta-repo"' >> $HOME/.bashrc
echo 'export shared_path="/feta-repo"' >> $VAGRANT_HOME/.bashrc

# Run provision scripts for classifiers
mkdir -p /opt/python/
for provision_script in `find $shared_path/clfs/ -name provision.sh`; do
     $provision_script
done;
