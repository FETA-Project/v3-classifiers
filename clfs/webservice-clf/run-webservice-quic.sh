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
        -i f:$shared_path/clfs/webservice-clf/sample_data/sample_quic.trapcap,f:webservice_quic_out.trapcap:buffer=off \
        --config-path $shared_path/clfs/webservice-clf/models/QUIC-NN/dataset-configuration.yaml \
        --model-path $shared_path/clfs/webservice-clf/models/QUIC-NN/best-checkpoint-102-W-2022-44-99344186d9-420-0.pickle \
        --data-root $shared_path/clfs/webservice-clf/datasets/CESNET-QUIC22
elif [ "$model" == "lightgbm" ]; then
    echo "Selected model: LightGBM"
    $shared_path/clfs/webservice-clf/bin/prediction_module.py \
        -i f:$shared_path/clfs/webservice-clf/sample_data/sample_quic.trapcap,f:webservice_quic_out.trapcap:buffer=off \
        --config-path $shared_path/clfs/webservice-clf/models/QUIC-LightGBM/dataset-configuration.yaml \
        --model-path $shared_path/clfs/webservice-clf/models/QUIC-LightGBM/lightgbm-model-102-W-2022-44-99344186d9-420-0.txt \
        --data-root $shared_path/clfs/webservice-clf/datasets/CESNET-QUIC22
else
    echo "Invalid model option: $model"
    echo "Options: nn, lightgbm"
    exit 1
fi
