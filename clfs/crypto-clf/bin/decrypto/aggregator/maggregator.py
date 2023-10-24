#!/usr/bin/env python3


import pytrap
import os, sys, time, argparse
from src.FlowCache import FlowCache
from src.ReasonsDefinition import *


### CONFIG ###
ACTIVE_TIMEOUT = 5 # flows
PASSIVE_TIMEOUT = 30 # minutes
DROP_ALONE_DST = False
MIN_ML_ALERTS = 3 # flows
SHOULD_CONTINUE = True

### PYTRAP FORMATS DEFINITIONS ###
IN_SPECS = "ipaddr DST_IP,ipaddr SRC_IP,uint16 SRC_PORT,uint16 DST_PORT,uint8 PROTOCOL,uint64 BYTES,uint64 BYTES_REV,uint32 PACKETS,uint32 PACKETS_REV,time DETECT_TIME,time TIME_FIRST,time TIME_LAST,uint8 PREDICTION,string EXPLANATION,string TLS_SNI"
OUT_SPEC = "ipaddr DST_IP,ipaddr SRC_IP,uint16 SRC_PORT,uint16 DST_PORT,uint64 FLOWS_TOTAL,uint64 BYTES_TOTAL,uint64 PACKETS_TOTAL,time EVENT_TIME,time CEASE_TIME,time DETECT_TIME,string DETECTION_SOURCE,time WIN_START_TIME,time WIN_END_TIME,uint32 STRATUM,uint32 DST,uint32 ML,uint8 ROTATED,string TLS_SNI"
### PYTRAP FORMATS DEFINITIONS ###

# Pytrap `stop` definition
stop = False


def sendToOutput(trapCtx, outUr, data, lastFlowTime):
    """
    Function for sending alerts to output IFC.
    Parameters:
        trapCtx: pytrap context
        outUr: output UniRec message
        data: alerts to send
    """
    winEndTime = pytrap.UnirecTime.fromDatetime(lastFlowTime)
    for flowRecord in data:
        outUr.SRC_IP = flowRecord.srcIp
        outUr.DST_IP = flowRecord.dstIp
        outUr.SRC_PORT = flowRecord.srcPort
        outUr.DST_PORT = flowRecord.dstPort
        outUr.DETECT_TIME = flowRecord.detectTime
        outUr.EVENT_TIME = flowRecord.eventTime
        outUr.CEASE_TIME = flowRecord.ceaseTime
        outUr.FLOWS_TOTAL = flowRecord.flows
        outUr.PACKETS_TOTAL = flowRecord.packets
        outUr.BYTES_TOTAL = flowRecord.bytes
        outUr.DETECTION_SOURCE = flowRecord.reasonToStr()
        outUr.WIN_START_TIME = flowRecord.winStartTime
        outUr.WIN_END_TIME = winEndTime
        outUr.STRATUM = flowRecord.reasons[REASON_STRATUM]
        outUr.DST = flowRecord.reasons[REASON_DST]
        outUr.ML = flowRecord.reasons[REASON_ML]
        outUr.ROTATED = 1 if flowRecord.rotated else 0
        outUr.TLS_SNI = flowRecord.sni

        trapCtx.send(outUr.getData(), 0)


def flowExporter(trapCtx, outUr, cache):
    """
    Function for exporting flows from flow cache and sending them to output IFC.
    Parameters:
        trapCtx: pytrap context
        outUr: output UniRec message
        cache: flow cache
    """
    dataToExport = cache.toExport()
    if dataToExport:
        sendToOutput(trapCtx, outUr, dataToExport, cache.getLastFlowTime())


# Main
if __name__ == "__main__":
    # Arguments definition
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--active-timeout", help=f"Max number of flows, when this number is reached, data are sent to out IFC, default is {ACTIVE_TIMEOUT} flows", type=int, default=ACTIVE_TIMEOUT)
    parser.add_argument("-m", "--min-ml-flows", help=f"At least {MIN_ML_ALERTS} flows needed to produce an alert with only ML flows", type=int, default=MIN_ML_ALERTS)
    parser.add_argument("-p", "--passive-timeout", help=f"Number of minutes, when this number of minutes passed from last activity, data are sent to out IFC, default is {PASSIVE_TIMEOUT} minutes", type=int, default=PASSIVE_TIMEOUT)
    parser.add_argument("-i", help="IFC interfaces for pytrap", type=str)
    parser.add_argument("-r", "--rotate-addresses", help="Rotate SRC and DST IP addresses and ports if DST port > SRC port", action='store_const', const=True)
    parser.add_argument("-d", "--drop-dst-only", help="Drop alerts with only DST", action='store_const', const=True)
    parser.add_argument("-v", action='store_const', const=True)

    # Arguments parsing
    args = parser.parse_args()
    ACTIVE_TIMEOUT = args.active_timeout
    PASSIVE_TIMEOUT = args.passive_timeout * 60 # to seconds
    MIN_ML_ALERTS = args.min_ml_flows
    ROTATE = args.rotate_addresses is not None
    DROP_ALONE_DST = args.drop_dst_only is not None

    # Flow cache init
    flowCache = FlowCache(ACTIVE_TIMEOUT, PASSIVE_TIMEOUT, MIN_ML_ALERTS, ROTATE, DROP_ALONE_DST)

    # Pytrap init
    trap = pytrap.TrapCtx()
    trap.init(sys.argv, 1, 1)

    fmtTypeIn = pytrap.FMT_UNIREC
    fmtSpecIn = IN_SPECS

    trap.setRequiredFmt(0, pytrap.FMT_UNIREC, IN_SPECS)
    rec = pytrap.UnirecTemplate(fmtSpecIn)

    out = pytrap.UnirecTemplate(OUT_SPEC)
    out.createMessage(8192)
    trap.setDataFmt(0, pytrap.FMT_UNIREC, OUT_SPEC)

    # Main program loop
    while not stop and SHOULD_CONTINUE:
        try:
            data = trap.recv()
        except pytrap.FormatChanged as e:
            fmtTypeIn, fmtSpecIn = trap.getDataFmt(0)
            rec = pytrap.UnirecTemplate(fmtSpecIn)
            data = e.data
        except KeyboardInterrupt:
            SHOULD_CONTINUE = False
            break

        if len(data) <= 1:
            SHOULD_CONTINUE = False
        else:
            receivedFlow = rec.copy()
            receivedFlow.setData(data)
            currentFlowTime = receivedFlow.TIME_LAST.toDatetime()

            if receivedFlow.PREDICTION == 1:
                flowCache.update(currentFlowTime, receivedFlow)

            flowExporter(trap, out, flowCache)

    # Cleanup
    dataToExport = flowCache.getAll()
    if dataToExport:
        sendToOutput(trap, out, dataToExport, flowCache.getLastFlowTime())

    trap.finalize()
