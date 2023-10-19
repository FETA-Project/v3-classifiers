#!/bin/bash

# (C) 2023 CESNET z.s.p.o. Prague, Czech Republic
# (C) 2023 FIT CTU in Prague, Czech Republic
# (C) 2023 FIT VUT in Brno, Czech Republic

export shared_path="/feta-repo"
export venv_path="/opt/python/ssh-clf/venv"
source $venv_path/bin/activate

$shared_path/clfs/ssh-clf/bin/ssh_classifier/ssh_classifier.py --no-buffer --mac-classifier-path $shared_path/clfs/ssh-clf/bin/ssh_classifier/ssh-mac-classifier.pkl -x -i f:$shared_path/clfs/ssh-clf/sample_data/ssh.trapcap,f:ssh_out.trapcap:buffer=off