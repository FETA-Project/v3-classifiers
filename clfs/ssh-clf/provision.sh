#!/bin/bash

echo "Running provision script for SSH classifier..."

export shared_path="/feta-repo"
export venv_path="/opt/python/ssh-clf/venv"

if [ -f $venv_path/bin/activate ]; then
    echo "Virtual environment already exists"
else 
    python3.9 -m venv $venv_path
fi

source $venv_path/bin/activate
pip3 install -r $shared_path/clfs/ssh-clf/requirements.txt

cp $shared_path/clfs/ssh-clf/run-ssh.sh $HOME/run-ssh.sh

echo "Provision of SSH classifier finished."