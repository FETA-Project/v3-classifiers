#!/bin/bash

echo "Running provision script for Miner classifier..."

clf_home="`dirname $0`"

export shared_path="/feta-repo"

for i in `ls $clf_home/rpm/*.rpm`; do
	dnf install -y --skip-broken $i
done;

cp $clf_home/run-miner-det.sh $VAGRANT_HOME/run-miner-det.sh

echo "Provision of Miner classifier finished."
