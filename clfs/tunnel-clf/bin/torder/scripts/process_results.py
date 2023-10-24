#!/usr/bin/env python3

import sys


def findIdByName(header, name):
	parts = header.split(",")
	for idx, part in enumerate(parts):
		p = part.split(' ')
		if p[1] == name:
			return idx
	return -1


def loadData():
	with open('./results.csv', 'rt') as src:
		lines = src.readlines()
		header = lines[0]
		data = lines[1:]

		torDetectionId = findIdByName(header, "TOR_DETECTED")

		torConnections = 0
		flowsProcessed = 0

		for flow in data:
			parts = flow.split(',')
			print(parts[torDetectionId])
			if parts[torDetectionId] == '1':
				torConnections += 1
			flowsProcessed += 1

		print(f'Tor connections : {torConnections} / {flowsProcessed}')


def main():
	loadData()
	pass


if __name__ == "__main__":
	main()
