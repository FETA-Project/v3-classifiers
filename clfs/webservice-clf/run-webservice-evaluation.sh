#!/bin/bash

# (C) 2023 CESNET z.s.p.o. Prague, Czech Republic
# (C) 2023 FIT CTU in Prague, Czech Republic
# (C) 2023 FIT VUT in Brno, Czech Republic

export shared_path="/feta-repo"
export venv_path="/opt/python/webservice-clf/venv"
source "$venv_path/bin/activate"

# Check if the protocol argument is provided
if [ $# -ne 1 ]; then
    echo "Usage: $0 <protocol>"
    echo "Options: tls, quic"
    exit 1
fi

protocol="$1"
export PYTHONPATH=$PYTHONPATH:$shared_path/clfs/webservice-clf/bin

# Check if the provided protocol is valid
if [[ "$protocol" == "TLS" || "$protocol" == "tls" ]]; then
    echo "Selected protocol: TLS"
    python -m evaluation_module \
        -i f:webservice_tls_out.trapcap \
        --config-path $shared_path/clfs/webservice-clf/models/TLS-NN/dataset-configuration.yaml \
        --data-root $shared_path/clfs/webservice-clf/datasets/CESNET-TLS-Year22
elif [[ "$protocol" == "QUIC" || "$protocol" == "quic" ]]; then
    echo "Selected protocol: QUIC"        
    python -m evaluation_module \
        -i f:webservice_quic_out.trapcap \
        --config-path $shared_path/clfs/webservice-clf/models/QUIC-NN/dataset-configuration.yaml \
        --data-root $shared_path/clfs/webservice-clf/datasets/CESNET-QUIC22
else
    echo "Invalid protocol option: $protocol"
    echo "Options: tls, quic"
    exit 1
fi