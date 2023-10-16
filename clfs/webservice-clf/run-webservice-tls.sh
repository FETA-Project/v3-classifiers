#!/bin/bash
export shared_path="/feta-repo"

source $shared_path/clfs/webservice-clf/venv/bin/activate

# Use neural network model
$shared_path/clfs/webservice-clf/bin/prediction_module.py \
    -i f:$shared_path/clfs/webservice-clf/sample_data/sample-tls.trapcap,f:webservice-tls-out.trapcap:buffer=off \
    --config-path $shared_path/clfs/webservice-clf/models/TLS-NN/dataset-configuration.yaml \
    --model-path $shared_path/clfs/webservice-clf/TLS-NN/best-checkpoint-174-M-2022-9-c524b2ccf6-420-0.pickle \
    --data-root $shared_path/clfs/webservice-clf/datasets/CESNET-TLS-Year22

# Use LightGBM model
# $shared_path/clfs/webservice-clf/bin/prediction_module.py \
#     -i f:$shared_path/clfs/webservice-clf/sample_data/sample-tls.trapcap,f:webservice-tls-out.trapcap:buffer=off \
#     --config-path $shared_path/clfs/webservice-clf/models/TLS-LightGBM/dataset-configuration.yaml \
#     --model-path $shared_path/clfs/webservice-clf/TLS-LightGBM/lightgbm-model-174-M-2022-9-c524b2ccf6-420-0.txt \
#     --data-root $shared_path/clfs/webservice-clf/datasets/CESNET-TLS-Year22