#!/bin/bash


# Check if the detector argument is provided
if [ $# -ne 1 ]; then
    echo "Usage: $0 <detector>"
    echo "Options: tunder, torder"
    exit 1
fi

detector="$1"

if [[ "$detector" == "TUNDER" || "$detector" == "tunder" ]]; then
    echo "Selected detector: TUNDER..."
    sleep 1
    $shared_path/clfs/tunnel-clf/bin/tunder/extras/visualizers/detector2txt.py tunder_output.trapcap 
elif [[ "$detector" == "TORDER" || "$detector" == "torder" ]]; then
    echo "Selected detector: TORDER..."
    sleep 1;
    $shared_path/clfs/tunnel-clf/bin/torder/extras/visualizers/torder2csv.py torder_output.trapcap
else
    echo "Invalid protocol detector: $detector"
    echo "Options: torder, tunder"
    exit 1
fi