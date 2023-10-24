# TunDer Reborn
TunDer is a detector of covert communicaton tunnels, mainly OpenVPN, WireGuard and Tor. Initial project can be found [here](https://gitlab.liberouter.org/feta/wif-group/tunder). It uses similar architecture and many principles, which were already introduced in [MalDer](https://gitlab.liberouter.org/feta/wif-group/malder).

TunDer consists of several weak detectors. There are two port detectors - the first for detection of default OpenVPN port 1194 and the second for detection of default WireGuard port 51820. Then, there are three detectors, one for processing of every one of the OVPN_CONF_LEVEL, WG_CONF_LEVEL, and SSA_CONF_LEVEL fields. Then, a detector of Tor relay nodes is present. Moreover, a blocklist detector, which checks whenever SRC_IP or DST_IP is present on user-provided blocklist.

Firstly, IP ranges are defined (in which we want to perform the detection), via the `--ip-ranges-file`. Then, detection is done in time windows and for every observed IP address (calculated from defined IP ranges) statistics are updated by weak detectors, when new flow arrives. Detectors receive flows, update their inner stores, and after the time window expires, rule matching is performed on the results of weak detectors, and an alert is sent to the output Unirec interface for every matched rule for each observed IP address.

## TunDer's Output Explanation
|Field|Explanation|
|---|---|
|SRC_IP|Observed IP address, where a covert communication tunnel was detected|
|RULE|String representation of matched rule|
|DETECT_TIME|Time of detection in the TunDer Detector|
|RESULT_PORT_OVPN|Result of the OVPN Port Detector|
|RESULT_PORT_WG|Result of the WG Port Detector|
|RESULT_CONF_LEVEL_OVPN|Result of the OVPN CONF_LEVEL Detector|
|RESULT_CONF_LEVEL_WG|Result of the WG CONF_LEVEL Detector|
|RESULT_CONF_LEVEL_SSA|Result of the SSA CONF_LEVEL Detector|
|RESULT_TOR|Result of the Tor Detector|
|RESULT_BLOCKLIST|Result of the Blocklist Detector|
|EXPLANATION_PORT_OVPN|Explanation of the OVPN Port Detector|
|EXPLANATION_PORT_WG|Explanation of the WG Port Detector|
|EXPLANATION_CONF_LEVEL_OVPN|Explanation of the OVPN CONF_LEVEL Detector|
|EXPLANATION_CONF_LEVEL_WG|Explanation of the WG CONF_LEVEL Detector|
|EXPLANATION_CONF_LEVEL_SSA|Explanation of the SSA CONF_LEVEL Detector|
|EXPLANATION_TOR|Explanation of the Tor Detector|
|EXPLANATION_BLOCKLIST|Explanation of the Blocklist Detector|

## TunDer's Help Section
```
Help
========
TunDer is a detector of covert communicaton tunnels. It uses {OVPN,WG,SSA}_CONF_LEVEL fields for detection of OpenVPN and WireGuard. It consists of multiple weak detectors: CONF_LEVEL Detector for both OVPN, WG and SSA, Default Port Detector for both OVPN and WG, Tor Detector, and Blocklist Detector. Every detector can be customized: threshold for number of positive flows, which has to be seen in the time window, to consider detector in this time window to be positive. Moreover, a probability threshold can be set for CONF_LEVEL detectors, to define needed minimal value of CONF_LEVEL field, to consider flow positive. Results of weak detectors are observed for each IP address defined as observed. When time interval expires, rule matching takes place and every satisfied rule for each observed IP address generates an alert on the output interface, which describes results and explanations for each weak detector.

-d
   Enable debug mode [-]
   Default: false
-h
   Display help section [-]
   Default: false

--time-window-size
   Time Window Size of TunDer in seconds [unsigned]
   Default: 900
--ovpn-port-threshold
   Threshold for OVPN Port Detector [unsigned]
   Default: 5
--wg-port-threshold
   Threshold for WireGuard Port Detector [unsigned]
   Default: 5
--ovpn-conf-proba-threshold
   Minimal OVPN_CONF_LEVEL value considered positive [unsigned]
   Default: 50
--ovpn-conf-threshold
   Threshold for OVPN_CONF_LEVEL Detector [unsigned]
   Default: 5
--wg-conf-proba-threshold
   Minimal WG_CONF_LEVEL value considered positive [unsigned]
   Default: 50
--wg-conf-threshold
   Threshold for WG_CONF_LEVEL Detector [unsigned]
   Default: 5
--ssa-conf-proba-threshold
   Minimal SSA_CONF_LEVEL value considered positive [unsigned]
   Default: 50
--ssa-conf-threshold
   Threshold for SSA_CONF_LEVEL Detector [unsigned]
   Default: 5
--tor-threshold
   Threshold for Tor Detector [unsigned]
   Default: 5
--ip-ranges-file
   Path to observed IP ranges file [string]
   Default: /opt/tunder/ipRanges.txt
--blocklist-file
   Path to blocklist file [string]
   Default: /opt/tunder/blocklist.txt
--blocklist-tick-interval
   Interval in seconds, in which blocklist file is checked for changes [unsigned]
   Default: 30
--blocklist-threshold
   Threshold for Blocklist Detector [unsigned]
   Default: 5

Args must be always passed separated by space:
   OK:   -m model.pickle
   FAIL: -mmodel.pickle
```
