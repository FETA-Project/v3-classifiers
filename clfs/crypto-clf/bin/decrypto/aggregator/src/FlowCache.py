import xxhash
from threading import Lock
from src.FlowRecord import FlowRecord


class FlowCache:
    """
    FlowCache class.
    """
    def __init__(self, activeTimeout, passiveTimeout, minMlAlerts, rotate, dropAloneDst):
        """
        Init.
        Parameters:
            activeTimeout: number of flows needed for exporting record from cache
            passiveTimeout: number of seconds of inactivity after which record is exported
        """
        self.cache = {}
        self.activeTimeout = activeTimeout
        self.passiveTimeout = passiveTimeout
        self.minMlAlerts = minMlAlerts
        self.rotate = rotate
        self.dropAloneDst = dropAloneDst
        self.lastFlowTime = False

    def getLastFlowTime(self):
        return self.lastFlowTime

    def update(self, currentFlowTime, flow):
        """
        Method for adding/updating records in cache.
        Parameters:
            flow: received (miner) flow
        """
        key = self.flowKey(flow)

        if not self.lastFlowTime or currentFlowTime > self.lastFlowTime:
            self.lastFlowTime = currentFlowTime

        # If flow key is in cache, update it, otherwise add a new record
        if key in self.cache:
            self.cache[key].update(flow, currentFlowTime)
        else:
            self.cache[key] = FlowRecord(flow, currentFlowTime, self.rotate)

    def toExport(self):
        """
        Method for exporting records from flow cache.
        Only flows which meet at least one condition (activeTimeout or passiveTimeout) are exported.
        Returns: list of exported flow records
        """
        flowRecordsToExport = []
        for k in self.cache.copy():
            if self.cache[k].ready(self.lastFlowTime, self.activeTimeout, self.passiveTimeout):
                # If the record contains only ML alerts and less than MIN_ML_ALERTS
                if not self.cache[k].shouldDrop(self.minMlAlerts, self.dropAloneDst):
                    flowRecordsToExport.append(self.cache[k])
                self.cache.pop(k)
        return flowRecordsToExport

    def getAll(self):
        """
        Method to get all records currently in cache.
        Cache is cleared afterwards.
        Returns: list of records which were present in cache before clear
        """
        flowRecordsToExport = list(self.cache.values())
        self.cache = {}
        return flowRecordsToExport

    @staticmethod
    def flowKey(flow):
        """
        Static method for calculation of flow key.
        Parameters:
            flow: flow for which key is calculated
        Returns: SHA256 string which is used as a key into the flow cache
        """
        ipAddresses = [str(flow.SRC_IP), str(flow.DST_IP)]
        ipAddresses.sort()

        ports = [str(flow.SRC_PORT), str(flow.DST_PORT)]
        ports.sort()

        strKey = ','.join(ipAddresses + ports)
        return xxhash.xxh32(strKey.encode('utf-8')).hexdigest()
