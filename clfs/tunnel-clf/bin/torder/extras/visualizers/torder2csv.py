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
        flows = []

        for record in data:
                flow = {}
                parts = list(csv.reader([record], skipinitialspace=True))[0]
                for idx in range(len(parts)):
                        flow[keys[idx]] = parts[idx]

                flows.append(flow)

        return flows


def printFlow(flowId, flow):
    print(f'TORDER OUTPUT FLOW #{flowId}')
    print(f'  SRC_IP:SRC_PORT : {flow["SRC_IP"]}:{flow["SRC_PORT"]}')
    print(f'  DST_IP:DST_PORT : {flow["DST_IP"]}:{flow["DST_PORT"]}')
    print(f'  TIME FIRST      : {flow["TIME_FIRST"]}')
    print(f'  TIME LAST       : {flow["TIME_LAST"]}')

    print()

    print(f'  BYTES           : {flow["BYTES"]}')
    print(f'  BYTES REV       : {flow["BYTES_REV"]}')
    print(f'  PACKETS         : {flow["PACKETS"]}')
    print(f'  PACKETS REV     : {flow["PACKETS_REV"]}')


def printDelimiter():
    print('--------------------------')


def printFlows(flows):
    for flowId, flow in enumerate(flows):
        if flowId != 0:
            printDelimiter()
        printFlow(flowId, flow)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Wrong number of arguments!')
        print('Expected: ./trapcap2txt <trapcapFile>')
        exit(1)

    csvFile = f'{sys.argv[1]}.csv'
    trapcapToCsv(sys.argv[1], csvFile)
    data = loadData(csvFile)
    flows = parseData(data)
    printFlows(flows)
