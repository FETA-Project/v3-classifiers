#!/bin/bash


/usr/bin/torder --tick-interval 1 --tor-relays-file $shared_path/clfs/tunnel-clf/sample_data/tor_blocklist.txt \
-i f:$shared_path/clfs/tunnel-clf/sample_data/tunnel.trapcap,f:torder_output.trapcap
/usr/bin/tunder --blocklist-tick-interval 1 --ip-ranges-file $shared_path/clfs/tunnel-clf/sample_data/anonymized_ip_ranges.txt \
-i f:torder_output.trapcap,f:tunder_output.trapcap