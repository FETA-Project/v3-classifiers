# DeCrypto
DeCrypto is a NEMEA module for detection of cryptomining, based on libnemea++ and libwif.

It is shipped together with aggregator - NEMEA module, which is connected to the output of DeCrypto, aggregates its output based on flow key to make detection results more reliable. Reporter module is also provided, which is meant to forward aggregator's output to Warden system.

Standard deployment scenario looks as follows:
```
PREFILTER (optional) -> DECRYPTO -> AGGREGATOR -> REPORTER
```

See [sup-files](sup-files/) for example configuration for Nemea supervisor.

## DeCrypto's Help Section
DeCrypto has several functionalities, which can be enabled by CLI options. See help section provided below:
```
DeCrypto
========
  CryptoMiners Detector based on WIF.
  Built Sep  8 2023 13:31:01

Help
========
DeCrypto has one input interface with incoming flow data. The primary output interface contains standard alerts. The secondary output interface contains ML features and flow info - if and only if the --use-alf is specified. Otherwise this interface should be set to 'b:'.
  Example without ALF : decrypto -i u:flowData,u:alerts,b: <other args>
  Example wit ALF     : decrypto -i u:flowData,u:alerts,u:alfData <other args>

-b
   Python Bridge Path [str]
   Default: /opt/decrypto/runtime/bridge.py
-d
   Enable debug mode
   Default: false
-f
   Flow Buffer Size [unsigned]
   Default: 50000
-h
   Display help section [-]
   Default: false
-m
   ML Model Path, pickle format[str]
   Default: /opt/decrypto/runtime/rf.pickle
--dst
   DST Threshold [0..1]
   Default: 0.03
--ml
   ML Threshold [0..1]
   Default: 0.99
--no-rst-fin
   Filter flows with empty SNI and RST/FIN flags
   Default: false
--use-alf
   Send ML features and flow info for ALF to the secondary output interface
   Default: false

Args must be always passed separated by space:
   OK:   -m model.pickle
   FAIL: -mmodel.pickle
```

## DeCrypto's Output Explanation
This section briefly explains several fields from the DeCrypto's output alerts.

|Field|Explanation|
|---|---|
|DETECT_TIME|Time of detection in the DeCrypto detector (`UnirecTime::now()`)|
|EVENT_TIME|Value of TIME_FIRST of the first seen flow|
|CEASE_TIME|Value of TIME_LAST of the last seen flow, before export from Aggregator|
|WIN_START_TIME|Contains same value as the EVENT_TIME field|
|WIN_END_TIME|Time of the export from the Aggregator (`UnirecTime::now()`)|
|STRATUM|Number of flows, which were marked as a miner due to detection of Stratum|
|DST|Number of flows, which were marked as a miner by both TLS SNI and ML|
|ML|Number of flows, which were marked as a miner by ML only|
|ROTATED|Containts `1` if flows had their SRC and DST fields swapped, `0` otherwise (perfomed only when enabled by CLI argument)

## Known Problems
This section addresses known problems, which may sometimes occur.

### Missing Python packages
After installation it might be needed to install additional Python packages by using following commnad:
```
pip3 install numpy==1.15.4 xxhash
```

### Shared Libraries Loading Fix
```
LD_LIBRARY_PATH=/usr/local/lib64:$LD_LIBRARY_PATH
export LD_LIBRARY_PATH
```
