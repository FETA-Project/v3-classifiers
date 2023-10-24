#!/usr/bin/env python3

# Based on https://github.com/danieluhricek/bota/blob/master/scripts/update_tor_relays.py by Daniel Uhricek

import argparse
import logging
import sys

import requests

logging.basicConfig(format="%(levelname)s: %(message)s")
log = logging.getLogger()
log.setLevel(logging.INFO)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", help="destination file path")
    args = parser.parse_args()

    url = "https://onionoo.torproject.org/summary?running=true"
    r = requests.get(url)

    data = None

    if r.status_code == 200:
        data = r.json()
    else:
        log.critical(r.text)
        sys.exit(1)

    relays = set()
    for relay in data["relays"]:
        for ip in relay["a"]:
            if ip.startswith("["):
                ip = ip.strip("[]")

            relays.add(ip)

    count = 0
    with open(args.path, "w+") as f:
        for relay in relays:
            f.write(relay + "\n")
            count += 1

        log.info(f"{count} IP addresses saved to {args.path}")


if __name__ == "__main__":
    main()
