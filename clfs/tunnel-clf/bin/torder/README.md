# Tor Detector - TorDer
TorDer is a NEMEA module for detection of Tor connections, based on libnemea++ and libwif.

It requires a list of Tor relay nodes in a separate file, which is then supplied as an input argument, see Help section below. The file needs to hve one IP address per line in any order, both IPv4 and IPv6 are supported:
```
IPv4
IPv6
...
IPv4
```

## TorDer's Help Section
```
TorDer - v1.0.0
Help
========
TorDer has one input interface with incoming flow data. The primary output interface contains copy of the input flow with new fields describing detection result. TOR_DETECTED contains `1`, if either SRC_IP or DST_IP was found on current Tor relays file blocklist, `0` otherwise. Moreover, TOR_DIRECTION describes the direction: value `1` is present, if DST_IP is Tor relay, `-1` is SRC_IP is Tor relay. Value `0` is set, when Tor was not detected.

--tick-interval
   Interval in seconds, in which Tor relays file is checked for changes [unsigned]
   Default: 15
--tor-relays-file
   Tor relays file path (formatted as one IP per line) [str]
   Default: None

Args must be always passed separated by space:
   OK:   --tick-interval 10
   FAIL: --tick-interval10
```

## TorDer's Output Explanation
This section briefly explains TorDer's output fields.

Output template is affected by the input template. All fields from the input template are present in the output template as well, together with two new fields, which are described below. Values from all input fields are copied to the output record, therefore no field or information from the original flow is lost. Moreover, there is no prefilter present and all received flows will be present on the output interface.

|Type|Field|Explanation|
|---|---|---|
|uint8|TOR_DETECTED|Detection result, Tor **was not** detected - `0`, Tor **was** detected `1`|
|int8|TOR_DIRECTION|Which IP address was found on Tor relays blocklist, DST_IP - `1`, SRC_IP - `-1`, Neither - `0`|

## Setup
It is recommended to periodically update Tor relays blocklist when deploying TorDer, to keep the detection accuracy as high as possible.
There is a [script](./scripts/update_tor_relays.py), which downloads latest Tor relays and filter out duplicate IP addresses. TorDer periodically checks for file changes on the supplied Tor relays blocklist file and loads a new version, when last modification time is changed. Interval for new version check can be adjusted by `--tick-interval` argument, see the help section.

Crontab can be used to periodically call the script for Tor relays update at midnight and TorDer will automatically load a new version.
Use `crontab -e` to add the following line:
```
0 0 * * * /wif-dev/torder/scripts/update_tor_relays.py /wif-dev/torder/scripts/tor_ips.txt
```
And run TorDer:
```
./torder --tor-relays-file /wif-dev/torder/scripts/tor_ips.txt
```
