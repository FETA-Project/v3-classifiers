import os, sys
import pytrap
from src.ReasonsDefinition import *


CONFIRMED_MINING_POOL_PORTS = [
    3333,
    4444,
    5555,
    7777,
    12433,
    14433,
    14444,
    17777,
    20005,
    20128,
    20535
]


class FlowRecord:
    """
    FlowRecord class.
    Represents one record in the flow cache.
    """

    def __init__(self, firstFlow, currentFlowTime, doRotation):
        """
        Init.
        Parameters:
            firstFlow: first flow of the record
        """
        self.srcIp = firstFlow.SRC_IP
        self.dstIp = firstFlow.DST_IP
        self.srcPort = firstFlow.SRC_PORT
        self.dstPort = firstFlow.DST_PORT
        self.detectTime = firstFlow.DETECT_TIME
        self.eventTime = firstFlow.TIME_FIRST
        self.winStartTime = firstFlow.TIME_FIRST
        self.reasons = {
            REASON_STRATUM: 0,
            REASON_DST: 0,
            REASON_ML: 0
        }
        self.flows = 0
        self.packets = 0
        self.bytes = 0
        self.lastUpdate = 0
        self.rotated = False
        self.sniSet = False
        self.sni = ""
        self.handleRotation(doRotation)
        self.update(firstFlow, currentFlowTime)

    def update(self, flow, currentFlowTime):
        """
        Method to update statistics based on the newly received flow.
        Parameters:
            flow: newly received flow
        """
        self.flows += 1
        self.reasons[flow.EXPLANATION] += 1
        self.packets += flow.PACKETS + flow.PACKETS_REV
        self.bytes += flow.BYTES + flow.BYTES_REV
        self.ceaseTime = flow.TIME_LAST
        # Update last activity timestamp
        self.lastUpdate = currentFlowTime
        self.updateSni(flow)

    def ready(self, lastFlowTime, activeTimeout, passiveTimeout):
        """
        Method to check if record is ready to be exported.
        Parameters:
            activeTimeout: active timeout
            passiveTimeout: passive timeout
        Returns: True if flow should be exported, otherwise False
        """
        return (lastFlowTime - self.lastUpdate).total_seconds() >= passiveTimeout or self.flows >= activeTimeout

    def shouldDrop(self, minMlAlerts, dropAloneDst):
        # At least 1 Stratum will prevent the drop
        if self.reasons[REASON_STRATUM] > 0:
            return False

        # If we have at least 1 DST and at least 1 ML, prevent the drop
        if self.reasons[REASON_DST] > 0 and self.reasons[REASON_ML] > 0:
            return False

        # If we got here, there was no Stratum (1st IF)
        # And DST is 0 or ML is 0 (2nd IF)
        if self.reasons[REASON_DST] > 0:
            # DST is > 0
            return dropAloneDst and self.reasons[REASON_ML] == 0
        else:
            # ML is > 0
            return self.reasons[REASON_ML] < minMlAlerts

    def handleRotation(self, rotate):
        if not rotate or self.dstPort < 1024 or self.dstPort < self.srcPort or self.dstPort in CONFIRMED_MINING_POOL_PORTS:
            return
        srcIp = self.srcIp
        srcPort = self.srcPort
        self.srcIp = self.dstIp
        self.srcPort = self.dstPort
        self.dstIp = srcIp
        self.dstPort = srcPort
        self.rotated = True

    def updateSni(self, flow):
        if self.sniSet == False and flow.EXPLANATION == REASON_DST and len(flow.TLS_SNI) > 0:
            self.sni = flow.TLS_SNI
            self.sniSet = True

    def reasonToStr(self):
        """
        Method for getting the most dominant detection method.
        Returns: 'STRATUM', 'DST', 'DST and ML' or 'ML'
        """
        # STRATUM only
        if self.reasons[REASON_STRATUM] > 0 and self.reasons[REASON_DST] == 0 and self.reasons[REASON_ML] == 0:
            return 'STRATUM'
        # DST only
        if self.reasons[REASON_DST] > 0 and self.reasons[REASON_ML] == 0:
            return 'DST'
        # DST and ML
        if self.reasons[REASON_DST] > 0 and self.reasons[REASON_ML] > 0:
            return 'DST and ML'
        # ML
        return 'ML'
