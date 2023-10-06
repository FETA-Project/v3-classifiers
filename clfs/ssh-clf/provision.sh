#!/bin/bash

echo "Running provision script for SSH classifier..."

export shared_path="/feta-repo"

cd `dirname $0`

if [ -f venv/bin/activate ]; then
    echo "Virtual environment already exists"
else 
    python3.9 -m venv venv
fi

source venv/bin/activate

pip3 install -r requirements.txt

cp $shared_path/clfs/ssh-clf/run.sh $HOME/run.sh

echo "Provision of SSH classifier finished."
