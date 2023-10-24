#!/bin/bash

echo "Running provision script for Tunnel classifier..."

clf_home="`dirname $0`" 

for i in `ls $clf_home/rpm/*.rpm`; do
        echo $i
	dnf install -y --skip-broken $i
done;

cp run-tunnel-det.sh $VAGRANT_HOME/run-tunnel-det.sh

echo "Provision of Tunnel classifier finished."
