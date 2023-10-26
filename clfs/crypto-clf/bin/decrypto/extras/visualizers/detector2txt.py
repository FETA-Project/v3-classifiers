#!/usr/bin/env python3
import csv
import os
import sys


def trapcapToCsv(src, dst):
    cmd = f'/usr/bin/nemea/logger -t -i f:{src} > {dst}'
    os.system(cmd)


def loadData(fileName):
        with open(fileName, 'rt') as src:
                lines = src.readlines()
                lines = [l[:-1] for l in lines if l]
                return lines


def parseTemplate(template):
        pairs = template.split(',')
        keys = [p.split(' ')[1] for p in pairs]
        return keys


def parseData(data):
        template = data[0]
        data = data[1:]

        keys = parseTemplate(template)
        alerts = []

        for record in data:
                alert = {}
                parts = list(csv.reader([record], skipinitialspace=True))[0]
                for idx in range(len(parts)):
                        alert[keys[idx]] = parts[idx]

                alerts.append(alert)

        return alerts


def printAlert(alertId, alert):
    prediction = "True" if alert["PREDICTION"] == '1' else "False"
    sni =  alert["TLS_SNI"] if len(alert["TLS_SNI"]) > 0 else "- empty -"

    print(f'DECRYPTO ALERT #{alertId}')
    print(f'  SRC_IP:SRC_PORT : {alert["SRC_IP"]}:{alert["SRC_PORT"]}')
    print(f'  DST_IP:DST_PORT : {alert["DST_IP"]}:{alert["DST_PORT"]}')
    print(f'  PREDICTION      : {prediction}')
    print(f'  EXPLANATION     : {alert["EXPLANATION"]}')

    print()

    print(f'  DETECT TIME     : {alert["DETECT_TIME"]}')
    print(f'  FIRST TIME      : {alert["TIME_FIRST"]}')
    print(f'  LAST TIME       : {alert["TIME_LAST"]}')

    print()

    print(f'  TLS SNI         : {sni}')
    print(f'  BYTES           : {alert["BYTES"]}')
    print(f'  BYTES REV       : {alert["BYTES_REV"]}')
    print(f'  PACKETS         : {alert["PACKETS"]}')
    print(f'  PACKETS REV     : {alert["PACKETS_REV"]}')


def printDelimiter():
    print('--------------------------')


def printAlerts(alerts):
    for alertId, alert in enumerate(alerts):
        if alertId != 0:
            printDelimiter()
        printAlert(alertId, alert)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Wrong number of arguments!')
        print('Expected: ./trapcap2txt <trapcapFile>')
        exit(1)

    csvFile = f'{sys.argv[1]}.csv'
    trapcapToCsv(sys.argv[1], csvFile)
    data = loadData(csvFile)
    alerts = parseData(data)
    printAlerts(alerts)
