#!/bin/bash
export shared_path="/feta-repo"

source $shared_path/clfs/webservice-clf/venv/bin/activate

# Use neural network model
$shared_path/clfs/webservice-clf/bin/prediction_module.py \
    -i f:$shared_path/clfs/webservice-clf/sample_data/sample-quic.trapcap,f:webservice-quic-out.trapcap:buffer=off \
    --config-path $shared_path/clfs/webservice-clf/models/QUIC-NN/dataset-configuration.yaml \
    --model-path $shared_path/clfs/webservice-clf/QUIC-NN/best-checkpoint-102-W-2022-44-99344186d9-420-0.pickle \
    --data-root $shared_path/clfs/webservice-clf/datasets/CESNET-QUIC22

# Use LightGBM model
# $shared_path/clfs/webservice-clf/bin/prediction_module.py \
#     -i f:$shared_path/clfs/webservice-clf/sample_data/sample-quic.trapcap,f:webservice-quic-out.trapcap:buffer=off \
#     --config-path $shared_path/clfs/webservice-clf/models/QUIC-LightGBM/dataset-configuration.yaml \
#     --model-path $shared_path/clfs/webservice-clf/QUIC-LightGBM/lightgbm-model-102-W-2022-44-99344186d9-420-0.txt \
#     --data-root $shared_path/clfs/webservice-clf/datasets/CESNET-QUIC22
