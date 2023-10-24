#!/usr/bin/env python3

import sys


def loadData():
	with open('./test.csv', 'rt') as src:
		lines = src.readlines()
		header = lines[0]
		data = lines[1:]

		#print(f'{len(lines)} ?= {len(data) + 1}')

		srcIps = []
		dstIps = []

		for flow in data:
			parts = flow.split(',')
			srcIps.append(parts[0])
			dstIps.append(parts[1])

		return srcIps, dstIps


def loadBlocklist():
	with open('./scripts/tor_ips.txt', 'rt') as src:
		blocklist = src.readlines()
		blocklist = [l.strip() for l in blocklist]
		return blocklist


def isBlocklisted(blocklist, ip):
	for blockedIp in blocklist:
		if blockedIp == ip:
			return True
	return False


def matchBlocklist(srcIps, dstIps, blocklist):
	cnt = len(srcIps)
	torConnections = 0
	for i in range(cnt):
		if isBlocklisted(blocklist, srcIps[i]) or isBlocklisted(blocklist, dstIps[i]):
			torConnections += 1
	print(f'Tor connections: {torConnections} / {cnt}')


def main():
	srcIps, dstIps = loadData()
	blocklist = loadBlocklist()

	#print(blocklist)
	#exit(0)

	matchBlocklist(srcIps, dstIps, blocklist)

	pass


if __name__ == "__main__":
	main()
