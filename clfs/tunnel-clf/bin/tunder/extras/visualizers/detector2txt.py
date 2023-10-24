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
    print(f'TUNDER ALERT #{alertId}')
    print(f'  IP ADDRESS    : {alert["SRC_IP"]}')
    print(f'  DETECT TIME   : {alert["DETECT_TIME"]}')
    print(f'  MATCHED RULE  : {alert["RULE"]}')

    print()

    print(f'  CONF LVL OVPN : {alert["RESULT_CONF_LEVEL_OVPN"]}')
    if alert["RESULT_CONF_LEVEL_OVPN"] != '0':
        print(f'    REASON      : {alert["EXPLANATION_CONF_LEVEL_OVPN"]}')

    print(f'  CONF LVL WG   : {alert["RESULT_CONF_LEVEL_WG"]}')
    if alert["RESULT_CONF_LEVEL_WG"] == '1':
        print(f'    REASON      : {alert["EXPLANATION_CONF_LEVEL_WG"]}')

    print(f'  CONF LVL SSA  : {alert["RESULT_CONF_LEVEL_SSA"]}')
    if alert["RESULT_CONF_LEVEL_SSA"] == '1':
        print(f'    REASON      : {alert["EXPLANATION_CONF_LEVEL_SSA"]}')

    print(f'  PORT OVPN     : {alert["RESULT_PORT_OVPN"]}')
    if alert["RESULT_PORT_OVPN"] == '1':
        print(f'    REASON      : {alert["EXPLANATION_PORT_OVPN"]}')

    print(f'  PORT WG       : {alert["RESULT_PORT_WG"]}')
    if alert["RESULT_PORT_WG"] == '1':
        print(f'    REASON      : {alert["EXPLANATION_PORT_WG"]}')

    print(f'  TOR           : {alert["RESULT_TOR"]}')
    if alert["RESULT_TOR"] == '1':
        print(f'    REASON      : {alert["EXPLANATION_TOR"]}')

    print(f'  BLOCKLIST     : {alert["RESULT_BLOCKLIST"]}')
    if alert["RESULT_BLOCKLIST"] == '1':
        print(f'    REASON      : {alert["EXPLANATION_BLOCKLIST"]}')


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
