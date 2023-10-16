#!/bin/bash

echo "Running provision script for web service classifier..."

export shared_path="/feta-repo"

cd `dirname $0`

if [ -f venv/bin/activate ]; then
    echo "Virtual environment already exists"
else 
    python3.11 -m venv venv
fi

source venv/bin/activate

pip3 install -r requirements.txt

cp $shared_path/clfs/web-service-clf/run-webservice-tls.sh $HOME/run-webservice-tls.sh
cp $shared_path/clfs/web-service-clf/run-webservice-quic.sh $HOME/run-webservice-quic.sh

echo "Provision of web service classifier finished."
