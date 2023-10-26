#!/bin/bash

echo "Running provision script for Tunnel classifier..."

clf_home="`dirname $0`" 

for i in `ls $clf_home/rpm/*.rpm`; do
        echo $i
	dnf install -y $i
done;

#create blocklist file
if [ ! -f /opt/tunder/blocklist.txt ]; then
    mkdir -p /opt/tunder/
    touch /opt/tunder/blocklist.txt;
    chmod 777 /opt/tunder/blocklist.txt;
fi

cp $clf_home/run-tunnel-det.sh $VAGRANT_HOME/run-tunnel-det.sh
cp $clf_home/run-tunnel-visualiser.sh $VAGRANT_HOME/run-tunnel-visualiser.sh

echo "Provision of Tunnel classifier finished."
