#!/bin/bash

echo "Running provision script for web services classifier..."

export shared_path="/feta-repo"
export venv_path="/opt/python/webservice-clf/venv"

if [ -f $venv_path/bin/activate ]; then
    echo "Virtual environment already exists"
else 
    python3.11 -m venv $venv_path
fi

source $venv_path/bin/activate
python3.11 -m pip install -r $shared_path/clfs/webservice-clf/requirements.txt

cp $shared_path/clfs/webservice-clf/run-webservice-tls.sh $HOME/run-webservice-tls.sh
cp $shared_path/clfs/webservice-clf/run-webservice-quic.sh $HOME/run-webservice-quic.sh
cp $shared_path/clfs/webservice-clf/run-webservice-evaluation.sh $HOME/run-webservice-evaluation.sh

echo "Provision of web services classifier finished."