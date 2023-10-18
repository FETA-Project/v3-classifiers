#!/bin/bash
export shared_path="/feta-repo"
export venv_path="/opt/python/webservice-clf/venv"
source $venv_path/bin/activate

# Check if the model argument is provided
if [ $# -ne 1 ]; then
    echo "Usage: $0 <model>"
    echo "Options: nn, lightgbm"
    exit 1
fi

model="$1"

# Check if the provided model is valid
if [ "$model" == "nn" ]; then
    echo "Selected model: Neural network"
    $shared_path/clfs/webservice-clf/bin/prediction_module.py \
        -i f:$shared_path/clfs/webservice-clf/sample_data/sample_tls.trapcap,f:webservice_tls_out.trapcap:buffer=off \
        --config-path $shared_path/clfs/webservice-clf/models/TLS-NN/dataset-configuration.yaml \
        --model-path $shared_path/clfs/webservice-clf/models/TLS-NN/best-checkpoint-174-M-2022-9-c524b2ccf6-420-0.pickle \
        --data-root $shared_path/clfs/webservice-clf/datasets/CESNET-TLS-Year22
elif [ "$model" == "lightgbm" ]; then
    echo "Selected model: LightGBM"
    $shared_path/clfs/webservice-clf/bin/prediction_module.py \
        -i f:$shared_path/clfs/webservice-clf/sample_data/sample_tls.trapcap,f:webservice_tls_out.trapcap:buffer=off \
        --config-path $shared_path/clfs/webservice-clf/models/TLS-LightGBM/dataset-configuration.yaml \
        --model-path $shared_path/clfs/webservice-clf/models/TLS-LightGBM/lightgbm-model-174-M-2022-9-c524b2ccf6-420-0.txt \
        --data-root $shared_path/clfs/webservice-clf/datasets/CESNET-TLS-Year22
else
    echo "Invalid model option: $model"
    echo "Options: nn, lightgbm"
    exit 1
fi