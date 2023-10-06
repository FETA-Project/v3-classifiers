#!/usr/bin/env python3

import pytrap
import sys
import argparse
import binascii
import numpy as np
import pandas as pd
import queue
import threading
import warnings
warnings.simplefilter(action='ignore', category=FutureWarning)
pd.set_option('mode.chained_assignment', None)

from flow_data import DIR_TO, DIR_FROM, ResultAuth, ResultAuthMethod, ResultAuthTiming, ResultTrafficType, FlowData
from traffic_type_detector import TrafficTypeDetector
from authentication_detector import AuthenticationDetector
from timing_detector import TimingDetector
from machine_learning_model import MachineLearningModel

#Traffic directions
# DIR_TO = 1
# DIR_FROM = -1

#Older ipfixprobe require this values
# DIR_TO = b'\x01'
# DIR_FROM = b'\xff'

#Preprocess
FILTER_ARRAY_FIELDS = ["PPI_PKT_LENGTHS", "PPI_PKT_DIRECTIONS", "PPI_PKT_FLAGS", "PPI_PKT_TIMES"]

#------------------------------------------------------------------------------------------------
def preprocess(data):
    """
    TODO
    Plan to preproces anomally or similar traffic

    data: input flows variable
    """
    # if data["is_ssh"]:
        #merge packets wit 16 tcp flag with the following
    while 16 in data["PPI_PKT_FLAGS"]:
        ind = data["PPI_PKT_FLAGS"].index(16)
        if ind+1 < len(data["PPI_PKT_FLAGS"]) and data["PPI_PKT_DIRECTIONS"][ind+1] == data["PPI_PKT_DIRECTIONS"][ind]:  #is not the last element and following packet has the same direction
            data["PPI_PKT_LENGTHS"][ind+1] += data["PPI_PKT_LENGTHS"][ind]
            for i in FILTER_ARRAY_FIELDS:
                data[i].pop(ind)
        else:
            data["PPI_PKT_FLAGS"][ind] = 0   #mark as 0 for prevent infinite loop, but dont pop or merge packets
        # pass

    # while 1 in data['PPI_PKT_LENGTHS']:
    #     ind_1 = data['PPI_PKT_LENGTHS'].index(1)
    #     for field in FILTER_ARRAY_FIELDS:
    #         x = data[field]
    #         # if ind_1 < len(x):
    #         x.pop(ind_1)
    #         if field == "PPI_PKT_DIRECTIONS":
    #             x = [int(i.hex(), 16) for i in x]
    #         # setattr(data, field, x)
    #         data[field] = x

#------------------------------------------------------------------------------------------------
def export_result(data, alert, DEBUG, trap):
    """
    Prepare IFC alert with the given flow data.

    - rec: Basic IP flow
    - tags: Detector results
    """

    alert.DST_IP = data["DST_IP"]
    alert.SRC_IP = data["SRC_IP"]
    alert.BYTES = data["BYTES"]
    alert.BYTES_REV = data["BYTES_REV"]
    alert.LINK_BIT_FIELD = data["LINK_BIT_FIELD"]
    alert.TIME_FIRST = data["TIME_FIRST"]
    alert.TIME_LAST = data["TIME_LAST"]
    alert.PACKETS = data["PACKETS"]
    alert.PACKETS_REV = data["PACKETS_REV"]
    alert.DST_PORT = data["DST_PORT"]
    alert.SRC_PORT = data["SRC_PORT"]
    alert.AUTHENTICATION_RESULT = data["result"].name
    alert.AUTHENTICATION_METHOD = data["method"].name
    alert.AUTHENTICATION_TIMING = data["timing"].name
    alert.TRAFFIC_CATEGORY = data["traffic_type"].name

    if DEBUG == True:
        alert.PPI_PKT_DIRECTIONS = data["PPI_PKT_DIRECTIONS"]
        alert.PPI_PKT_FLAGS = data["PPI_PKT_FLAGS"]
        alert.PPI_PKT_LENGTHS = data["PPI_PKT_LENGTHS"]
        alert.PPI_PKT_TIMES = data["PPI_PKT_TIMES"]

    trap.send(alert.getData(), 0)

#------------------------------------------------------------------------------------------------
def get_mac_features(flow):
    """
    Helper function extract features for ML to predict ciphersuite category.
    Multiple enc/MAC ciphersuite options results in same packet sizes. Instead of focusing to predict the exact algorithm, we split possible combinations into several categories (naming convention: block_size + MAC_size, e.g. 8  + 16). Classifier does not care about the cipher so much (only it's block size). More important is to determine the correct MAC algorithm (respectively it's length), because the appended length is projected into every packet information we have.
    Function is_in_category have different meaning of categories (using naming min_size+block_size) and is used as a feature for ML. This feature also overlaps (fully nested) and have more exlusionary characteristics, which could not be reflected in the shorter communication.

    - data: input flows variable
    """


    features = {
    'ssh-userauth': None,
    'bs8': False,
    '16+8n': False,
    '20+8n': False,
    '24+8n': False,
    '28+8n': False,
    '32+8n': False,
    '40+8n': False,
    '44+8n': False,
    '72+8n': False,
    '76+8n': False,
    '24+16n': False,
    '28+16n': False,
    '32+16n': False,
    '36+16n': False,
    '40+16n': False,
    '48+16n': False,
    '52+16n': False,
    '80+16n': False,
    '84+16n': False,
    # 'no_category': False
    }
    #c_ssh-userauth - SSH_MSG_SERVICE_REQUEST
    features["ssh-userauth"] = flow.PPI_PKT_LENGTHS[flow.auth_start] if flow.auth_start > 0 and flow.auth_start < len(flow.PPI_PKT_LENGTHS)-1 else 0

    #bs8 - check difference between packet sizes (could leak 8B block size info)
    if flow.auth_start > 0 and flow.auth_start < len(flow.PPI_PKT_LENGTHS):
        a = list(set(flow.PPI_PKT_LENGTHS[flow.auth_start:]))  #uniq packet sizes after packet 16
        for i in range(len(a)):
            for j in a[i+1:]: #look only forward (behind was check by previous iteration)
                if (int(a[i]) - int(j)) % 16 and (int(a[i]) - int(j)) % 8 == 0:
                    features["bs8"] = True
                    break
            if features["bs8"]:
                break
    else:
        pass

    # print(is_in_category(8, 8, flow.PPI_PKT_LENGTHS[vals["has16"]+1:], 16))
    #possible categories based on packet lenghts
    #- categories are included in each other - no need to check all of them
    if is_in_category(8, 8, flow.PPI_PKT_LENGTHS[flow.pckt_16_index:], 16):
        #16+8n
        features['16+8n'] = True
        if is_in_category(8, 16, flow.PPI_PKT_LENGTHS[flow.pckt_16_index:], 24):
            features['24+8n'] = True
            if is_in_category(8, 20, flow.PPI_PKT_LENGTHS[flow.pckt_16_index:], 32, True):
                features['32+8n'] = True
                if is_in_category(8, 32, flow.PPI_PKT_LENGTHS[flow.pckt_16_index:], 40):
                    features['40+8n'] = True
                    if is_in_category(8, 64, flow.PPI_PKT_LENGTHS[flow.pckt_16_index:], 72):
                        features['72+8n'] = True
                        if is_in_category(16, 64, flow.PPI_PKT_LENGTHS[flow.pckt_16_index:], 80):
                            features['80+16n'] = True
                    if is_in_category(16, 20, flow.PPI_PKT_LENGTHS[flow.pckt_16_index:], 40, True):
                        features['40+16n'] = True
                    if is_in_category(16, 32, flow.PPI_PKT_LENGTHS[flow.pckt_16_index:], 48):
                        features['48+16n'] = True
                if is_in_category(16, 16, flow.PPI_PKT_LENGTHS[flow.pckt_16_index:], 32):
                    features['32+16n'] = True
            if is_in_category(16, 8, flow.PPI_PKT_LENGTHS[flow.pckt_16_index:], 24):
                features['24+16n'] = True

    elif is_in_category(8, 12, flow.PPI_PKT_LENGTHS[flow.pckt_16_index:], 20):
        #20+8n
        features['20+8n'] = True
        if is_in_category(8, 20, flow.PPI_PKT_LENGTHS[flow.pckt_16_index:], 28):
            features['28+8n'] = True
            if is_in_category(8, 32, flow.PPI_PKT_LENGTHS[flow.pckt_16_index:], 44, True):
                features['44+8n'] = True
                if is_in_category(8, 64, flow.PPI_PKT_LENGTHS[flow.pckt_16_index:], 76, True):
                    features['76+8n'] = True
                    if is_in_category(16, 64, flow.PPI_PKT_LENGTHS[flow.pckt_16_index:], 84, True):
                        features['84+16n'] = True
                if is_in_category(16, 32, flow.PPI_PKT_LENGTHS[flow.pckt_16_index:], 52, True):
                    features['52+16n'] = True
            if is_in_category(16, 12, flow.PPI_PKT_LENGTHS[flow.pckt_16_index:], 28):
                features['28+16n'] = True
            if is_in_category(16, 20, flow.PPI_PKT_LENGTHS[flow.pckt_16_index:], 36):
                features['36+16n'] = True

    else:
        # some iplementatins (e.g. OpenSSH) send 2 SSH messages (e.g. global request not specified by RFC) in the same packet
        # for MTE MAC it is no problem, but for ETM MAC and chacha-poly you calculate the second size header (4B) in packet size, leading to missmatch all categories
        # features["no_category"] = True
        pass

    return pd.Series(features)

#------------------------------------------------------------------------------------------------
def is_in_category(bs, ms, arr, min_size, mac_etm = False):
    """
    Helper function check if the given sequence of packet sizes is valid for the given ciphersuite parameters (block size, MAC size, min packet length, EtM/MtE mode).


    - bs:       block size
    - ms:       mac size
    - arr:      packet lengths
    - min_size: minimum packet size
    - mac_etm:  MAC EtM mode (bool)
    """

    etm = 0
    if mac_etm:
        #EtM mode does not encrypt MAC tag AND MESSAGE LENGTH (4B) so the message is padded to cipher block size (min 4B padding, block multiple of 8B) differently.
        etm = 4
    for i in arr:
        #cython?
        #check if every packet (encrypted part) is multiple of the given block size (as required in the RFC)
        if ((int(i) - ms - etm) % bs == 0) == False or int(i) < min_size:
            return False
    return True

#------------------------------------------------------------------------------------------------
class SSHClassifier():
    """
    Main control class for reading IFC records from pytrap and main SSH classifier logic
    """

    
    # define required pytrap input/output specication
    SINGLE_IFC_PYTRAP_INPUT_SPECIFICATION = "ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,uint64 BYTES_REV,uint64 LINK_BIT_FIELD,time TIME_FIRST,time TIME_LAST,uint32 PACKETS,uint32 PACKETS_REV,uint16 DST_PORT,uint16 SRC_PORT,bytes IDP_CONTENT,bytes IDP_CONTENT_REV,int8* PPI_PKT_DIRECTIONS,uint8* PPI_PKT_FLAGS,uint16* PPI_PKT_LENGTHS,time* PPI_PKT_TIMES,uint32* D_PHISTS_IPT,uint32* D_PHISTS_SIZES,uint32* S_PHISTS_IPT,uint32* S_PHISTS_SIZES"
    PYTRAP_OUTPUT_SPECIFICATION = "ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,uint64 BYTES_REV,uint64 LINK_BIT_FIELD,time TIME_FIRST,time TIME_LAST,uint32 PACKETS,uint32 PACKETS_REV,uint16 DST_PORT,uint16 SRC_PORT,string AUTHENTICATION_RESULT,string AUTHENTICATION_METHOD,string AUTHENTICATION_TIMING,string TRAFFIC_CATEGORY"
    PYTRAP_EXTENDED_OUTPUT_SPECIFICATION = "ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,uint64 BYTES_REV,uint64 LINK_BIT_FIELD,time TIME_FIRST,time TIME_LAST,uint32 PACKETS,uint32 PACKETS_REV,uint16 DST_PORT,uint16 SRC_PORT,string AUTHENTICATION_RESULT,string AUTHENTICATION_METHOD,string AUTHENTICATION_TIMING,string TRAFFIC_CATEGORY,int8* PPI_PKT_DIRECTIONS,uint8* PPI_PKT_FLAGS,uint16* PPI_PKT_LENGTHS,time* PPI_PKT_TIMES"

    #--------------------------------------------------------------------------------------------
    def __init__(self, mac_pkl, stdout = False, debug = False, recv_timeout = 10, recv_messages = 10000, max_queue_size = 10):
        """
        Initialize class and set all given parameters.

        - mac_pkl:          path to ML pkl for MAC algorithm predicting
        - single_ifc:       use ipfix one IFC merged format, instead od multiple Unirec IFC
        - stdout:           don't export result and print to stdout instead
        - debug:            append pstats info to exported results
        - recv_timeout:     recvBulk Timeout in seconds before interrupt of capture
        - recv_messages:    recvBulk Maximum number of messages to capture, infinite when -1
        - max_queue_size:   max size of queue used for producer-consumer data handoff
        """

        #Prepare variable for templates and incomming flows
        self.ifc = None
        self.stdout = stdout
        self.debug = debug
        self.data = {}
        self.trap = pytrap.TrapCtx()
        self.initialized = False
        self.mac_predictor = MachineLearningModel(mac_pkl)
        self.timing_detector = TimingDetector()
        self.authentication_detector = AuthenticationDetector(self.mac_predictor)
        self.traffic_type_detector = TrafficTypeDetector()
        self.recv_timeout = recv_timeout
        self.recv_messages = recv_messages
        self.running = True
        self.recordsToProcess = queue.Queue(maxsize = max_queue_size)

    #--------------------------------------------------------------------------------------------
    def __del__(self):
        """
        Free allocated TRAP IFCs
        """

        self.trap.finalize()

    #--------------------------------------------------------------------------------------------
    def fetch_record(self):
        """
        Fetch records from pytrap, (for all used IFC if not merged using ipfix -x)
        """

        #Receive input flow record from NEMEA
        return FlowData(self.trap.recvBulk(self.ifc, time = self.recv_timeout, count = self.recv_messages))
        
        # if len(rec) <= 1:
        #     raise Exception()
        # self.ifc.setData(rec)

    #--------------------------------------------------------------------------------------------
    def initialize(self):
        """
        Initialize pytrap IFC interfaces for receiving and sending messages
        """

        if self.initialized:
            print("SSHClassifier seems to be already initialized. Skipping...", file=sys.stderr)
            return

        #Set the required number of the input/output (IFC) to pytrap variable
        #Set module input/outputs parameters
        self.trap.init(sys.argv, 1, 1 if not self.stdout else 0)

        #Set required unirec format and define required input fields
        self.trap.setRequiredFmt(0, pytrap.FMT_UNIREC, SSHClassifier.SINGLE_IFC_PYTRAP_INPUT_SPECIFICATION)
        self.ifc = pytrap.UnirecTemplate(SSHClassifier.SINGLE_IFC_PYTRAP_INPUT_SPECIFICATION)

        #Set the output field list
        self.alert = pytrap.UnirecTemplate(SSHClassifier.PYTRAP_OUTPUT_SPECIFICATION if not self.debug else SSHClassifier.PYTRAP_EXTENDED_OUTPUT_SPECIFICATION)

        #Allocate memory for the UNIREC alert template and set the data output IFC format
        if not self.stdout:
            # set the data format to the output IFC
            self.trap.setDataFmt(0, pytrap.FMT_UNIREC, SSHClassifier.PYTRAP_OUTPUT_SPECIFICATION if not self.debug else SSHClassifier.PYTRAP_EXTENDED_OUTPUT_SPECIFICATION)
            #Allocate memory for the alert, we do not have any variable fields, so no argument is needed.
            self.alert.createMessage(65000)
        else:
            #print fields header for stdout output option
            print(SSHClassifier.PYTRAP_OUTPUT_SPECIFICATION if not self.debug else SSHClassifier.PYTRAP_EXTENDED_OUTPUT_SPECIFICATION)

        self.initialized = True

    #--------------------------------------------------------------------------------------------
    def do_detection(self, records):
        """
        Main detector logic. Runs detections functions in specific order and store results

        - records: FlowData with multiple flow records
        """
        
        #apply preprocess functions
        records.data.apply(lambda x: preprocess(x), axis=1)     #TODO
        # records['has16'] = records.apply(lambda x: has_16(x), axis=1)
        # records['auth_start'] = records.apply(lambda x: auth_start(x), axis=1)


        # NOTE auth_start and pckt_16_index needs to be already defined in DataFrame
        # TODO change get_mac_features to process whole FlowData instead of one flow record (than implicit "lazy load" will work)
        records.auth_start #dummy for defining auth_start and pckt_16_index
        features_df = records.data.apply(lambda x: get_mac_features(x), axis=1)

        #ML predict MAC category
        records.data['mac_category'] = self.mac_predictor.predict(features_df)

        #mac category names in ML and here are not exactly same due to EtM/MtE mode (change in ML?)
        records.mac_category.replace("8 + 20", "8 + 24").replace("8 + 32", "8 + 36").replace("8 + 64", "8 + 68").replace("16 + 32", "16 + 36").replace("16 + 64", "16 + 68")

        #run clasification
        self.run_detectors(records)
        return

    #--------------------------------------------------------------------------------------------
    def run_detectors(self, records):
        """
        Run detectors on given flow record. Return classification tags.

        - data:   flow record
        """

        records.data[['result', 'method']] = self.authentication_detector.detect(records)
        records.data['timing'] = self.timing_detector.detect(records)
        records.data['traffic_type'] = self.traffic_type_detector.detect(records, np.where(records.data['result'] == ResultAuth.auth_ok))

        return 

    #--------------------------------------------------------------------------------------------
    def producer(self):
        """
        Producer logic. This method is called in a separate thread. It receives flow data from the
        input ifc and store it in the queue for processing by consumer thread.
        """
        
        # Main detector loop
        while self.running:
            try:
                records = self.fetch_record()
            except Exception as e:
                self.running = False
                print(e)
                continue

            if records.len() > 0:
                self.recordsToProcess.put(records)
            else:
                # Empty buffer
                self.running = False
                pass

    #--------------------------------------------------------------------------------------------
    def consumer(self):
        """
        Consumer logic. This method is called in a separate thread. It takes flow data from the queue, performs
        detection and sends results to the output ifc.
        """

        cnt = 0

        # Producer runs until no new flows are received and all already received are processed
        while self.running or not self.recordsToProcess.empty():
            try:
                # timeout=5: every 5 seconds when no flow data was received, queue.Empty is thrown and
                # I can check, if I should continue or end
                records = self.recordsToProcess.get(timeout=5)
                # start detection for all records in buffer
                self.do_detection(records)
                if not self.stdout:
                    records.data.apply(lambda row: export_result(row, self.alert, self.debug, self.trap), axis=1)
                    cnt += records.len()
                else:
                    print(records.data)
                self.recordsToProcess.task_done()
            except queue.Empty:
                pass

    #--------------------------------------------------------------------------------------------
    def main(self):
        """
        This only method should be called after creating SSHClassifier object.
        Use it as a entry point, it initialize all pytrap requirements, manage records reading in loop, buffering and finally run classification.

        """

        self.initialize()

        producer = threading.Thread(target=self.producer)
        consumer = threading.Thread(target=self.consumer)

        producer.start()
        consumer.start()

        producer.join()
        consumer.join()
    #---------------------------------------------------------------------------------------------

# ------------------------------------------------------------------------------------------------
def main():

   #Explicit parse options for single IFC from ipfix collector or NEMEA multiple IFC
    parser = argparse.ArgumentParser(prog='NEMEA SSH detector')
    # parser.add_argument('-x', '--ipfix', action='store_true', help='Single input IFC format from IPFIX collector')
    parser.add_argument('--stdout', action='store_true', help='Write output to stdout instead of Unirec')
    parser.add_argument('--debug', action='store_true', help='Add pstats info into the output IFC')
    parser.add_argument('--mac-classifier-path', default=None, help='Path to the python pkl object with MAC classifier')
    parser.add_argument('--recv_timeout', default=10, help='recvBulk Timeout in seconds before interrupt of capture.')
    parser.add_argument('--recv_messages', default=10000, help='recvBulk Maximum number of messages to capture, infinite when -1')
    parser.add_argument('--max_queue_size', default=10, help='Max size of queue used for producer-consumer data handoff')
    args, unknown = parser.parse_known_args()

    ssh_classifier = SSHClassifier(args.mac_classifier_path, args.stdout, args.debug, args.recv_timeout, args.recv_messages, args.max_queue_size)
    ssh_classifier.main()

#------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    main()
