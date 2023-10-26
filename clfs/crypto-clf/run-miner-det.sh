#!/bin/bash


/usr/bin/decrypto/decrypto -i "f:$shared_path/clfs/crypto-clf/sample_data/mining.trapcap,f:miner_out.trapcap,b:"
$shared_path/clfs/crypto-clf/bin/decrypto/extras/visualizers/detector2txt.py miner_out.trapcap 