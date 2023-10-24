#!/usr/bin/python3


import argparse
from report2idea import *


# Module name, description and required input data format
MODULE_NAME = "miner_detector_ml"
MODULE_DESC = "Converts output of minerdetector and mineraggregator module to IDEA."

REQ_TYPE = pytrap.FMT_UNIREC
REQ_FORMAT = "ipaddr DST_IP,ipaddr SRC_IP,uint16 SRC_PORT,uint16 DST_PORT,uint64 FLOWS_TOTAL,uint64 BYTES_TOTAL,uint64 PACKETS_TOTAL,time EVENT_TIME,time CEASE_TIME,time DETECT_TIME,string DETECTION_SOURCE,time WIN_START_TIME,time WIN_END_TIME,uint32 STRATUM,uint32 DST,uint32 ML,uint8 ROTATED,string TLS_SNI"


def prepareDetectionString(rec):
    detectionSources = []
    if rec.STRATUM > 0:
        detectionSources.append(f'{rec.STRATUM}x Stratum')
    if rec.DST > 0:
        detectionSources.append(f'{rec.DST}x DST')
    if rec.ML > 0:
        detectionSources.append(f'{rec.ML}x ML')

    if len(rec.TLS_SNI) > 0:
        detectionSources.append(f'TLS SNI: {rec.TLS_SNI}')

    return ', '.join(detectionSources)


def rotatedToStr(rec):
    if rec.ROTATED == 1:
        return ' [Rotated]'
    else:
        return ''


# Main conversion function
def convert_to_idea(rec, opts=None):
    endTime = getIDEAtime(rec.DETECT_TIME)
    idea = {
        "Format": "IDEA0",
        "ID": getRandomId(),
        # Now
        "CreateTime": getIDEAtime(),
        "DetectTime": getIDEAtime(rec.DETECT_TIME),
        "EventTime": getIDEAtime(rec.EVENT_TIME),
        "CeaseTime": getIDEAtime(rec.CEASE_TIME),
        "Category": [ "Suspicious.Miner" ],
        "Source": [{
              "Proto": [ 'tcp' ],
              "Port": [ rec.SRC_PORT ]
         }],
        "Target": [{
              "Proto": [ 'tcp' ],
              "Port": [ rec.DST_PORT ]
        }],
        'Node': [{
            'Name': 'undefined',
            'SW': [ 'Nemea', 'miner_detector_ml' ],
            'Type': [ 'Flow', 'Statistical', 'Signature' ]
        }],
    }

    idea['FlowCount'] = rec.FLOWS_TOTAL
    idea['PacketCount'] = rec.PACKETS_TOTAL
    idea['ByteCount'] = rec.BYTES_TOTAL
    idea['WinStartTime'] = getIDEAtime(rec.WIN_START_TIME)
    idea['WinEndTime'] = getIDEAtime(rec.WIN_END_TIME)

    """
    TODO:
        * Better Module Name.
        * Own Module Description.
        * Node, Note & Description - Own string texts.
    """

    setAddr(idea['Source'][0], rec.SRC_IP)
    setAddr(idea['Target'][0], rec.DST_IP)
    idea['Description'] = f'Source IP {rec.SRC_IP} might be a miner, based on {rec.DETECTION_SOURCE}'
    idea['Note'] = f"{rec.SRC_IP}:{rec.SRC_PORT} connected to {rec.DST_IP}:{rec.DST_PORT}{rotatedToStr(rec)}. Detection based on: {prepareDetectionString(rec)}"
    return idea


if __name__ == "__main__":
    Run(
        module_name = MODULE_NAME,
        module_desc = MODULE_DESC,
        req_type = REQ_TYPE,
        req_format = REQ_FORMAT,
        conv_func = convert_to_idea,
        arg_parser = None
    )
