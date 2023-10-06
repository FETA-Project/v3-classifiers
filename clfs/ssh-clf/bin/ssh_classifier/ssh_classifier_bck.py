#!/usr/bin/env python3

import pytrap
import sys
import binascii
import argparse
import pickle
import numpy as np
import warnings
warnings.simplefilter(action='ignore', category=FutureWarning)
import pandas as pd
pd.set_option('mode.chained_assignment', None)
from enum import Enum
from enum import auto as auto_id
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score


# Results
#------------------------------------------------------------------------------------------------
class ResultAuth(Enum):
    fail = auto_id()
    auth_ok = auto_id()
    unknown = auto_id()

#------------------------------------------------------------------------------------------------
class ResultAuthMethod(Enum):
    key = auto_id()
    password = auto_id()
    unknown = auto_id()

#------------------------------------------------------------------------------------------------
class ResultAuthTiming(Enum):
    user = auto_id()
    auto = auto_id()
    unknown = auto_id()

#------------------------------------------------------------------------------------------------
class ResultTrafficType(Enum):
    upload = auto_id()
    download = auto_id()
    terminal = auto_id()
    other = auto_id()
    unknown = auto_id()


# Constants
#------------------------------------------------------------------------------------------------

#SSH traffic filter
FILTER_SSH_string = [bytearray("SSH", 'utf-8')]
# FILTER_PORTS = [22,2222]

# define required pytrap input specication for single input IFC (ipfix)
SINGLE_IFC_PYTRAP_INPUT_SPECIFICATION = {"single_ifc": "ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,uint64 BYTES_REV,uint64 LINK_BIT_FIELD,time TIME_FIRST,time TIME_LAST,uint32 PACKETS,uint32 PACKETS_REV,uint16 DST_PORT,uint16 SRC_PORT,bytes IDP_CONTENT,bytes IDP_CONTENT_REV,int8* PPI_PKT_DIRECTIONS,uint8* PPI_PKT_FLAGS,uint16* PPI_PKT_LENGTHS,time* PPI_PKT_TIMES,uint32* D_PHISTS_IPT,uint32* D_PHISTS_SIZES,uint32* S_PHISTS_IPT,uint32* S_PHISTS_SIZES"}

# define required pytrap input specication for multiple input IFC (unirec)
MULTIPLE_IFC_PYTRAP_INPUT_SPECIFICATION = {"idpcontent": "ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,uint64 BYTES_REV,uint64 LINK_BIT_FIELD,time TIME_FIRST,time TIME_LAST,macaddr DST_MAC,macaddr SRC_MAC,uint32 PACKETS,uint32 PACKETS_REV,uint16 DST_PORT,uint16 SRC_PORT,uint8 DIR_BIT_FIELD,uint8 PROTOCOL,uint8 TCP_FLAGS,uint8 TCP_FLAGS_REV,bytes IDP_CONTENT,bytes IDP_CONTENT_REV",
                    "pstats": "ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,uint64 BYTES_REV,uint64 LINK_BIT_FIELD,time TIME_FIRST,time TIME_LAST,macaddr DST_MAC,macaddr SRC_MAC,uint32 PACKETS,uint32 PACKETS_REV,uint16 DST_PORT,uint16 SRC_PORT,uint8 DIR_BIT_FIELD,uint8 PROTOCOL,uint8 TCP_FLAGS,uint8 TCP_FLAGS_REV,int8* PPI_PKT_DIRECTIONS,uint8* PPI_PKT_FLAGS,uint16* PPI_PKT_LENGTHS,time* PPI_PKT_TIMES",
                    # "phists": "ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,uint64 BYTES_REV,uint64 LINK_BIT_FIELD,time TIME_FIRST,time TIME_LAST,macaddr DST_MAC,macaddr SRC_MAC,uint32 PACKETS,uint32 PACKETS_REV,uint16 DST_PORT,uint16 SRC_PORT,uint8 DIR_BIT_FIELD,uint8 PROTOCOL,uint8 TCP_FLAGS,uint8 TCP_FLAGS_REV,uint16* D_PHISTS_IPT,uint16* D_PHISTS_SIZES,uint16* S_PHISTS_IPT,uint16* S_PHISTS_SIZES"}
                    "phists": "ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,uint64 BYTES_REV,uint64 LINK_BIT_FIELD,time TIME_FIRST,time TIME_LAST,macaddr DST_MAC,macaddr SRC_MAC,uint32 PACKETS,uint32 PACKETS_REV,uint16 DST_PORT,uint16 SRC_PORT,uint8 DIR_BIT_FIELD,uint8 PROTOCOL,uint8 TCP_FLAGS,uint8 TCP_FLAGS_REV,uint32* D_PHISTS_IPT,uint32* D_PHISTS_SIZES,uint32* S_PHISTS_IPT,uint32* S_PHISTS_SIZES"}

PYTRAP_OUTPUT_SPECIFICATION = "ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,uint64 BYTES_REV,uint64 LINK_BIT_FIELD,time TIME_FIRST,time TIME_LAST,uint32 PACKETS,uint32 PACKETS_REV,uint16 DST_PORT,uint16 SRC_PORT,string AUTHENTICATION_RESULT,string AUTHENTICATION_METHOD,string AUTHENTICATION_TIMING,string TRAFFIC_CATEGORY"
PYTRAP_EXTENDED_OUTPUT_SPECIFICATION = PYTRAP_OUTPUT_SPECIFICATION + ",int8* PPI_PKT_DIRECTIONS,uint8* PPI_PKT_FLAGS,uint16* PPI_PKT_LENGTHS,time* PPI_PKT_TIMES"

#Traffic directions
DIR_TO = 1
DIR_FROM = -1

#Older ipfixprobe require this values
# DIR_TO = b'\x01'
# DIR_FROM = b'\xff'

#Preprocess
FILTER_ARRAY_FIELDS = ["PPI_PKT_LENGTHS", "PPI_PKT_DIRECTIONS", "PPI_PKT_FLAGS", "PPI_PKT_TIMES"]

SINGLE_IFC = False

#------------------------------------------------------------------------------------------------


# Thresholds
#------------------------------------------------------------------------------------------------

#Autentication
AUTH_INIT_THRESHOLD = 5
SESS_START_MIN = 11
AUTH_END_THRESHOLD = 20
PRE_AUTH_DIR_PATTERN = [DIR_TO, DIR_TO, DIR_FROM, DIR_TO, DIR_FROM] #SSH_NEWKEYS, SSH_MSG_SERVICE 2x,
PRE_AUTH_DIR_PATTERN_LEN = len(PRE_AUTH_DIR_PATTERN)
AUTH_KEY_DIR_PATTERN = [DIR_TO, DIR_FROM, DIR_TO, DIR_FROM]
AUTH_KEY_DIR_PATTERN_LEN = len(AUTH_KEY_DIR_PATTERN)
AUTH_PROB_OK_MIN = 30
AUTH_KEY_COEF = 0.65
AUTH_SUCCESS_PCKT = 50 #long mac can dramatically change success packet size (e.g. for 512b mac 84 bytes, which is above detection sensitivity)
AUTH_FAIL_POST_MAX = 3
REQ_RES = [DIR_TO, DIR_FROM]
REQ_RES_LEN = len(REQ_RES)
AUTH_KEY_MIN = 256
AUTH_PASS_MIN = 80
BUFFER_CNT = 1000
SSH_USERAUTH_VALUES= {32, 36, 40, 44, 48, 52, 56, 60, 64, 68, 88, 92, 96, 100}
MAC_CATEGORIES =  {
    '8 + 16': {'name': '8  + 16', 'ssh-userauth': 40, 'auth-success': 24, 'alt-name': ['8 + 12 etm']},
    '16 + 16': {'name': '16 + 16', 'ssh-userauth': 48, 'auth-success': 32, 'alt-name': ['16 + 12 etm']},
    '8 + 20': {'name': '8  + 20', 'ssh-userauth': 44, 'auth-success': 28, 'alt-name': ['8 + 16 etm']},
    '16 + 64': {'name': '16 + 64', 'ssh-userauth': 96, 'auth-success': 80, 'alt-name': ['']},
    '16 + 12': {'name': '16 + 12', 'ssh-userauth': 44, 'auth-success': 28, 'alt-name': ['16 + 8 etm']},
    '16 + 32': {'name': '16 + 32', 'ssh-userauth': 64, 'auth-success': 48, 'alt-name': ['']},
    '16 + 8': {'name': '16 + 8', 'ssh-userauth': 40, 'auth-success': 24, 'alt-name': ['']},
    '16 + 20': {'name': '16 + 20', 'ssh-userauth': 52, 'auth-success': 36, 'alt-name': ['16 + 16 etm']},
    '8 + 8': {'name': '8  + 8', 'ssh-userauth': 32, 'auth-success': 16, 'alt-name': ['']},
    '8 + 12': {'name': '8  + 12', 'ssh-userauth': 36, 'auth-success': 20, 'alt-name': ['8 + 8 etm']},
    '8 + 32': {'name': '8  + 32', 'ssh-userauth': 56, 'auth-success': 40, 'alt-name': ['']},
    '8 + 64': {'name': '8  + 64', 'ssh-userauth': 88, 'auth-success': 72, 'alt-name': ['']},
    '8 + 24': {'name': '8  + 24', 'ssh-userauth': 48, 'auth-success': 32, 'alt-name': ['8 + 20 etm']},
    '8 + 36': {'name': '8  + 36', 'ssh-userauth': 60, 'auth-success': 44, 'alt-name': ['8 + 32 etm']},
    '8 + 68': {'name': '8  + 68', 'ssh-userauth': 92, 'auth-success': 76, 'alt-name': ['8 + 64 etm']},
    '16 + 24': {'name': '16 + 24', 'ssh-userauth': 56, 'auth-success': 40, 'alt-name': ['16 + 20 etm']},
    '16 + 36': {'name': '16 + 36', 'ssh-userauth': 68, 'auth-success': 52, 'alt-name': ['16 + 32 etm']},
    '16 + 68': {'name': '16 + 68', 'ssh-userauth': 100, 'auth-success': 84, 'alt-name': ['16 + 64 etm']},
    }
# category    ssh-userauth    auth_succ   alernative category
# 8  + 16:    40              24          8+12etm
# 16 + 16:    48              32          16+12etm
# 8  + 20:    44              28          8+16etm
# 16 + 64:    96              80
# 16 + 12:    44              28          16+8etm
# 16 + 32:    64              48
# 16 + 8:     40              24
# 16 + 20:    52              36          16+16etm

#mimo ML? (nejsou v dat. sade, neni duvod/smysl nektery pouzivat)
# 8  + 8:     32              16
# 8  + 12:    36              20          8+8etm
# 8  + 32:    56              40
# 8  + 64:    88              72

#neexistuji MAC ke kategorii (pouze alternativni v etm - pojmenovani kvuli jednotnosti)
# 8  + 24:    48              32          8+20etm
# 8  + 36:    60              44          8+32etm
# 8  + 68:    92              76          8+64etm
# 16 + 24:    56              40          16+20etm
# 16 + 36:    68              52          16+32etm
# 16 + 68:    100             84          16+64etm


#Timing
HUMAN_AUTH_MIN_DELAY = 1 #seconds
HUMAN_AUTH_HOP_THRESHOLD = 1

#Data transfer
TRANSFER_TRESHOLD = 0.7


#------------------------------------------------------------------------------------------------
def is_ssh(data):
    """
    Filter valid SSH traffic (bidirectional). Function check if the connection flow is valid SSH traffic with enough data in both directions.

    - data: input flows variable
    """

    if data['IDP_CONTENT'][0:3] not in FILTER_SSH_string or \
       data['IDP_CONTENT_REV'][0:3] not in FILTER_SSH_string:# or \
       # data['DST_PORT'] not in FILTER_PORTS:
        return False
   #Extended filter
    if data['BYTES'] <= 60 or \
       data['BYTES_REV'] <= 60 or \
       data['PACKETS'] <= 5 or \
       data['PACKETS_REV'] <= 5 or \
       len(data['PPI_PKT_DIRECTIONS']) <= 10 or \
       data['PPI_PKT_DIRECTIONS'][0] != DIR_TO:
           return False
    return True

#------------------------------------------------------------------------------------------------
def preprocess(data):
    """
    TODO
    Plan to preproces anomally or similar traffic

    data: input flows variable
    """
    if data["is_ssh"]:
        #merge packets wit 16 tcp flag with the following
        while 16 in data["PPI_PKT_FLAGS"]:
            ind = data["PPI_PKT_FLAGS"].index(16)
            if ind+1 < len(data["PPI_PKT_FLAGS"]) and data["PPI_PKT_DIRECTIONS"][ind+1] == data["PPI_PKT_DIRECTIONS"][ind]:  #is not the last element and following packet has the same direction
                data["PPI_PKT_LENGTHS"][ind+1] += data["PPI_PKT_LENGTHS"][ind]
                for i in FILTER_ARRAY_FIELDS:
                    data[i].pop(ind)
            else:
                data["PPI_PKT_FLAGS"][ind] = 0   #mark as 0 for prevent infinite loop, but dont pop or merge packets
        pass

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
def has_16(data):
    """
    Helper function has_16 find a packet of lenght 16B after ciphersuite initialization is done and before authentication start.
    The majority of traffic send this packet separately (msg SSH_NEWKEYS) once the ciphersuite keys are established (end of SSH transport layer). Thus it is the last packet without encryption and alse MAC algorithm. With this information SSH Classifier is able to determine the exact point in traffic, where the transport layer ends respectively authentication layer begins, which is usefull for futher pattern detection.

    - data: input flows variable
    """


    has16 = 0
    #Packet length 16 signalize end of the SSH transport layer
    if 16 in data["PPI_PKT_LENGTHS"][AUTH_INIT_THRESHOLD:AUTH_END_THRESHOLD]:
        has16 = data["PPI_PKT_LENGTHS"][AUTH_INIT_THRESHOLD:AUTH_END_THRESHOLD].index(16) + AUTH_INIT_THRESHOLD

        #Some (server) implementation send SSH_NEWKEYS separated -> 2 packets 16 in row (oposite directions)
        while len(data["PPI_PKT_LENGTHS"]) > has16 + 1 and data["PPI_PKT_LENGTHS"][has16 + 1] == 16:
            has16 += 1

    # else:
    return has16

#------------------------------------------------------------------------------------------------
def auth_layer_pckt_index(arr, size):
    """
    Helper function checks the list of packets lenght values for the given length in the presumed authentication layer (threshold) of the SSH traffic and return it's index position.

    - arr:  list of packet lengths
    - size: searched packet size
    """

    if size in arr[AUTH_INIT_THRESHOLD:AUTH_END_THRESHOLD]:
        return arr[AUTH_INIT_THRESHOLD:AUTH_END_THRESHOLD].index(size) + AUTH_INIT_THRESHOLD
    else:
        return 0

#------------------------------------------------------------------------------------------------
def auth_start(data):
    """
    Function returns the position of the authentication layer begining. If 16B packet was already found, function returns it's position. If not, function tries to determine the position based on the packet length and direction pattern.
    Pattern should consist of client request (SSH_MSG_SERVICE_REQUEST) and server response of the same size (Different end/MAC algorithms are not supported). The packet size is also checked for valid values.
    SSH protocol uses message padding. Because SSH_MSG_SERVICE_REQUEST contain only static data, combined with the possible MAC algoritms we can define all valid packet sizes for this request.

    - data: input flows variable
    """


    auth_start = 0

    if not data["has16"] and len(data["PPI_PKT_LENGTHS"]) > SESS_START_MIN:
        for i in range(AUTH_INIT_THRESHOLD, min(len(data["PPI_PKT_LENGTHS"]), AUTH_END_THRESHOLD) - PRE_AUTH_DIR_PATTERN_LEN):
            if data["PPI_PKT_LENGTHS"][i] == data["PPI_PKT_LENGTHS"][i+1] and data["PPI_PKT_DIRECTIONS"][i] != data["PPI_PKT_DIRECTIONS"][i+1] and data["PPI_PKT_LENGTHS"][i] in SSH_USERAUTH_VALUES:
                #guess auth start from 'ssh-userauth' SSH_MSG_SERVICE_REQUEST (2 packets, same size, oposite directions, typical lenght - based on cipher/mac options)
                auth_start = i
                break
            elif data["PPI_PKT_DIRECTIONS"][i:i+PRE_AUTH_DIR_PATTERN_LEN] == PRE_AUTH_DIR_PATTERN:
                #guess based on direction pattern (NEWKEYS, 2x SSH_MSG_SERVICE_REQUEST, 2x ..)
                auth_start = i
                break

    return data["has16"] if (data["has16"] > 0 and len(data["PPI_PKT_LENGTHS"]) > data["has16"] + 1 ) else auth_start

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
def get_mac_features(data):
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
    features["ssh-userauth"] = int(data["PPI_PKT_LENGTHS"][data["auth_start"]+1])

    #bs8 - check difference between packet sizes (could leak 8B block size info)
    if data["auth_start"] > 0 and data["auth_start"] < len(data["PPI_PKT_LENGTHS"]):
        a = list(set(data["PPI_PKT_LENGTHS"][data["auth_start"]:]))  #uniq packet sizes after packet 16
        for i in range(len(a)):
            for j in a[i+1:]: #look only forward (behind was check by previous iteration)
                if (int(a[i]) - int(j)) % 16 and (int(a[i]) - int(j)) % 8 == 0:
                    features["bs8"] = True
                    break
            if features["bs8"]:
                break
    else:
        pass

    # print(is_in_category(8, 8, data["PPI_PKT_LENGTHS"][vals["has16"]+1:], 16))
    #possible categories based on packet lenghts
    #- categories are included in each other - no need to check all of them
    if is_in_category(8, 8, data["PPI_PKT_LENGTHS"][data["has16"]+1:], 16):
        #16+8n
        features['16+8n'] = True
        if is_in_category(8, 16, data["PPI_PKT_LENGTHS"][data["has16"]+1:], 24):
            features['24+8n'] = True
            if is_in_category(8, 20, data["PPI_PKT_LENGTHS"][data["has16"]+1:], 32, True):
                features['32+8n'] = True
                if is_in_category(8, 32, data["PPI_PKT_LENGTHS"][data["has16"]+1:], 40):
                    features['40+8n'] = True
                    if is_in_category(8, 64, data["PPI_PKT_LENGTHS"][data["has16"]+1:], 72):
                        features['72+8n'] = True
                        if is_in_category(16, 64, data["PPI_PKT_LENGTHS"][data["has16"]+1:], 80):
                            features['80+16n'] = True
                    if is_in_category(16, 20, data["PPI_PKT_LENGTHS"][data["has16"]+1:], 40, True):
                        features['40+16n'] = True
                    if is_in_category(16, 32, data["PPI_PKT_LENGTHS"][data["has16"]+1:], 48):
                        features['48+16n'] = True
                if is_in_category(16, 16, data["PPI_PKT_LENGTHS"][data["has16"]+1:], 32):
                    features['32+16n'] = True
            if is_in_category(16, 8, data["PPI_PKT_LENGTHS"][data["has16"]+1:], 24):
                features['24+16n'] = True

    elif is_in_category(8, 12, data["PPI_PKT_LENGTHS"][data["has16"]+1:], 20):
        #20+8n
        features['20+8n'] = True
        if is_in_category(8, 20, data["PPI_PKT_LENGTHS"][data["has16"]+1:], 28):
            features['28+8n'] = True
            if is_in_category(8, 32, data["PPI_PKT_LENGTHS"][data["has16"]+1:], 44, True):
                features['44+8n'] = True
                if is_in_category(8, 64, data["PPI_PKT_LENGTHS"][data["has16"]+1:], 76, True):
                    features['76+8n'] = True
                    if is_in_category(16, 64, data["PPI_PKT_LENGTHS"][data["has16"]+1:], 84, True):
                        features['84+16n'] = True
                if is_in_category(16, 32, data["PPI_PKT_LENGTHS"][data["has16"]+1:], 52, True):
                    features['52+16n'] = True
            if is_in_category(16, 12, data["PPI_PKT_LENGTHS"][data["has16"]+1:], 28):
                features['28+16n'] = True
            if is_in_category(16, 20, data["PPI_PKT_LENGTHS"][data["has16"]+1:], 36):
                features['36+16n'] = True

    else:
        # some iplementatins (e.g. OpenSSH) send 2 SSH messages (e.g. global request not specified by RFC) in the same packet
        # for MTE MAC it is no problem, but for ETM MAC and chacha-poly you calculate the second size header (4B) in packet size, leading to missmatch all categories
        # features["no_category"] = True
        pass

    return features

#------------------------------------------------------------------------------------------------
def detect_key(data):
    """
    Function detects key authentication with public key precheck based on directions and packet lenghts pattern.
    SSH authentication using public key and signature is designed in following pattern:
    1. client sends authentication precheck (SSH_MSG_USERAUTH_REQUEST) with it's public key and without signature to ensure that server know and accept this public key (optional)
    2. server either refuses public key (SSH_MSG_USERAUTH_FAILURE) or accept (SSH_MSG_USERAUTH_PK_OK) including received public key in the answer, which reflects on response packet size
    3. client sends authentication request again accompanied by a signature (using correct private key). The signature is next to the public key the largest element in the message. Adding signature makes the request size almost double of previous precheck.
    4. server verify signatures and either allow (SSH_MSG_USERAUTH_SUCCESS) or deny (SSH_MSG_USERAUTH_FAILURE) access. Detection can use predicted MAC algorithm to calculate the exact packet size of SSH_MSG_USERAUTH_SUCCESS message.

    - data: input flows variable
    """

    #skip 3 packets from authentication phase beginning: packet 16B, 2 SSH_MSG_SERVICE packets
    #repeat until the threshold or flow lenght, successful finding will also terminate this loop
    for i in range(data["auth_start"] + 3, \
        min(len(data["PPI_PKT_DIRECTIONS"]) - AUTH_KEY_DIR_PATTERN_LEN, AUTH_END_THRESHOLD)):

        #find directions pattern match required for the key authentication (->, <-, ->, <-)
        #and if so, verify detection packet size conditions
        if data["PPI_PKT_DIRECTIONS"][i:i+AUTH_KEY_DIR_PATTERN_LEN] == AUTH_KEY_DIR_PATTERN and \
           data["PPI_PKT_LENGTHS"][i+1] > data["PPI_PKT_LENGTHS"][i] * AUTH_KEY_COEF and \
           data["PPI_PKT_LENGTHS"][i+1] < data["PPI_PKT_LENGTHS"][i] and \
           data["PPI_PKT_LENGTHS"][i+2] > 2 * data["PPI_PKT_LENGTHS"][i] * AUTH_KEY_COEF and \
           data["PPI_PKT_LENGTHS"][i+3] <= MAC_CATEGORIES[data["mac_category"]]["auth-success"]:        #EDIT: try to guess searched packet size using MAC predict
                                                                                                        #TODO  try to test some threshold??
           # data["PPI_PKT_LENGTHS"][i+3] < AUTH_SUCCESS_PCKT:
            return ResultAuthMethod.key

    return ResultAuthMethod.unknown

#------------------------------------------------------------------------------------------------
def detect_auth_fail(data):
    """
    Function exclude flow where authentication cannot be completed (e.g. short communication). Function also call other detections.

    - data: input flows variable
    """
    #TODO split into logical order (or rename) in OOP detector class

    #packet size 28 in the SSH authentication layer use chacha-poly cipher, which should be the minimal packet length (only SSH message code). For authentication scope it means accepted login. Other ciphersuite combinations have different block size and MAC size and due to padding, it's can colaps with other messages.
    pckt28 = auth_layer_pckt_index(data["PPI_PKT_LENGTHS"], 28)

    #Packet 28 signalize successful authentication using chacha20-poly1305
    if pckt28 > 0:
        return ResultAuth.auth_ok

    #Longer connections are's almost sure authenticated
    #TODO should not happend in production env (not enough packets lengths captured)
    if len(data["PPI_PKT_LENGTHS"]) > AUTH_PROB_OK_MIN:
        return ResultAuth.auth_ok

    #not enough packets to complete authentication layer
    if len(data["PPI_PKT_LENGTHS"]) < SESS_START_MIN:
        return ResultAuth.fail

    #Too short connections cannot realize full authentication
    if data["auth_start"] + 6 >= len(data["PPI_PKT_LENGTHS"]) or \
       data["PPI_PKT_DIRECTIONS"][data["auth_start"]+1:].count(DIR_TO) < 3 or \
       data["PPI_PKT_DIRECTIONS"][data["auth_start"]+1:].count(DIR_FROM) < 3:
        #skip 2 packets (minimum) - SSH_MSG_SERVICE_REQUEST
        #skip 2 packets (minimum) - SSH_MSG_USERAUTH_REQUEST
        #skip 2 packets - some connection protocol action
        return ResultAuth.fail

    #try to detect authentication success based on specific packet length match (based on MAC knowledge)
    mac_auth_guess = detect_success_packet(data)
    # print(data["PPI_PKT_LENGTHS"], '\t', data["PPI_PKT_DIRECTIONS"], '\t', data['auth_start'], '  ', data["mac_category"], '  ', mac_auth_guess, detect_repeating(data))
    if mac_auth_guess == ResultAuth.auth_ok:
        return mac_auth_guess

    #try to detect auth in repeated authentications attempts
    return detect_repeating(data)

#------------------------------------------------------------------------------------------------
def detect_success_packet(data):
    """
    Authentication confirming packet contains only 1B SSH message code without any data. Authentication fail message contains a list of possible auth options, which makes this packet always longer. The size of confirming packet can be also calculated for every ciphersuite option. With MAC (and block size) prediction, we can look for these precalculated packet sizes.
    Function detects packet of the successfull autentication returned by the server (based on MAC prediciton)

    - data: input flows variable
    """

    #TODO
    #mac category names in ML and here are not exactly same (change in ML)
    if data["mac_category"] == "8 + 20":
        data["mac_category"] = "8 + 24"
    elif data["mac_category"] == "8 + 32":
        data["mac_category"] = "8 + 36"
    elif data["mac_category"] == "8 + 64":
        data["mac_category"] = "8 + 68"
    elif data["mac_category"] == "16 + 32":
        data["mac_category"] = "16 + 36"
    elif data["mac_category"] == "16 + 64":
        data["mac_category"] = "16 + 68"
    #TODO


    #first check, exactly matched mac category
    if MAC_CATEGORIES[data["mac_category"]]["auth-success"] in data["PPI_PKT_LENGTHS"][data["auth_start"]+4:]:
        ind = data["PPI_PKT_LENGTHS"][data["auth_start"]+4:].index(MAC_CATEGORIES[data["mac_category"]]["auth-success"]) + data["auth_start"]
        if data["PPI_PKT_DIRECTIONS"][ind] == DIR_FROM:
            #found a packet of the same size as the autentication confirmation packet for given MAC
            return ResultAuth.auth_ok

    #second check, other mac categories - use some difference threshold
    tmp = []
    for k, v in MAC_CATEGORIES.items():
        if v["auth-success"] in data["PPI_PKT_LENGTHS"][data["auth_start"]+4:]:
            ind = data["PPI_PKT_LENGTHS"][data["auth_start"]+4:].index(v["auth-success"]) + data["auth_start"]
            if data["PPI_PKT_DIRECTIONS"][ind] == DIR_FROM:
                #store potencial success
                d = abs(v["auth-success"] - MAC_CATEGORIES[data["mac_category"]]["auth-success"])
                if tmp:
                    if tmp[0][2] > d:
                        tmp = []
                        tmp.append((k, ind, d))
                    elif tmp[0][2] == d:
                        tmp.append((k, ind, d))
                else:
                    tmp.append((k, ind, d))
    if tmp:
        #potecial match found with other MAC category
        if tmp[0][2] == 0:                                                   #TODO create THRESHOLD
            return ResultAuth.auth_ok

    return ResultAuth.unknown

#------------------------------------------------------------------------------------------------
def detect_repeating(data):
    """
    Function detects repeated authentication tries and it's results, based on average response size. Client is offten allowed to try login several times in one connection. In repeated failing login pattern we should see the same server response (client request could slightly vary, e.g. +/- block size, depends on password lenght). Meassuring server response sizes (min, max, avg) we can confirm login failure if repeating if found until communication end or deduce login success if smaller response is found.

    - data: input flows variable
    """

    l = len(data["PPI_PKT_LENGTHS"])
    i = data["auth_start"] + 5 #skip authentication layer init (pckt 16, 2x SERVICE_REQUEST, none auth) req/resp
    avg_dst = 0
    cnt_dst = 0
    max_dst = 0
    min_dst = 0

    #Calculate sum of responses in selected packets
    # while i < l and data["PPI_PKT_LENGTHS"][i] > AUTH_SUCCESS_PCKT:
    while i < l and data["PPI_PKT_LENGTHS"][i] > MAC_CATEGORIES[data["mac_category"]]["auth-success"]:        #EDIT: try to guess searched packet size using MAC predict
                                                                                                                #TODO  try to test some threshold??
                                                                                                                #isn't is same as above while looking for smaller than auth_ok packet??
        if data["PPI_PKT_DIRECTIONS"][i] == DIR_FROM:
            avg_dst += data["PPI_PKT_LENGTHS"][i]
            cnt_dst += 1
            max_dst = max_dst if max_dst > data["PPI_PKT_LENGTHS"][i] else data["PPI_PKT_LENGTHS"][i]
            min_dst = min_dst if min_dst < data["PPI_PKT_LENGTHS"][i] else data["PPI_PKT_LENGTHS"][i]
        i += 1

    #cycle stoped before list end, (small packet was found)
    #probably authenticated
    if i < l - AUTH_FAIL_POST_MAX:
        return ResultAuth.auth_ok

    #Detect similar size in server responses (based on average difference)          #TODO avg_dst -> sum_dst
    if cnt_dst > 0:
        if max_dst - (avg_dst/cnt_dst) < avg_dst * 0.2 or \
           (avg_dst/cnt_dst) - min_dst < avg_dst * 0.2:
            return ResultAuth.fail

    return ResultAuth.unknown

#------------------------------------------------------------------------------------------------
def detect_user_auth(data):
    """
    The SSH connection is usualy initialized before password/key passphrase is known and user enter credentials at runtime. This should result in a time delay for writing before authentication request is send.
    Meassuring time delays before client request we can determine if the login is interactive or automatic. Passwords and keys stored in the keychain belongs to automatic login as well.
    Function detects the client time delays in authentication phase with a simple threshold, which automatic tool should not reach until explicitly set.

    - data: input flows variable
    """

    hop_counter = 0

    #Limit detection only for authentication phase (if possible)
    pckt28 = auth_layer_pckt_index(data["PPI_PKT_LENGTHS"], 28)
    stop = min(pckt28, AUTH_END_THRESHOLD) if pckt28 > 0 else AUTH_END_THRESHOLD

    if len(data["PPI_PKT_TIMES"]) > data["auth_start"] + 1:
        prev = data["PPI_PKT_TIMES"][data["auth_start"] + 1].getTimeAsFloat()
        for i, t in enumerate(data["PPI_PKT_TIMES"][data["auth_start"] + 1:stop], start=data["auth_start"]+1):
            delta = t.getTimeAsFloat() - prev
            prev = t.getTimeAsFloat()
            if data["PPI_PKT_DIRECTIONS"][i] == DIR_TO and \
               delta > HUMAN_AUTH_MIN_DELAY:
                hop_counter += 1

    if hop_counter >= HUMAN_AUTH_HOP_THRESHOLD:
        return ResultAuthTiming.user
    else:
        return ResultAuthTiming.auto

#------------------------------------------------------------------------------------------------
def detect_key_without_precheck(data):
    """
    As mention in detect_key, the public key precheck is optional and this step has no result in authentication result.
    Similar to password detection, function tries to detects key authentication without precheck based on threshold and response packet of minimal size. In contrast with password, the send key is usually much longer (ECC keys are much shorter, so the can look like very long password).

    - data: input flows variable
    """

    #skip packet 16 and 2 SSH_MSG_SERVICE
    for i in range(data["auth_start"] + 3, min(len(data["PPI_PKT_DIRECTIONS"]) - REQ_RES_LEN, AUTH_END_THRESHOLD)):
        if data["PPI_PKT_DIRECTIONS"][i:i+REQ_RES_LEN] == REQ_RES and \
           data["PPI_PKT_LENGTHS"][i] > AUTH_KEY_MIN and \
           data["PPI_PKT_LENGTHS"][i+1] <= MAC_CATEGORIES[data["mac_category"]]["auth-success"]:        #EDIT: try to guess searched packet size using MAC predict
                                                                                                        #TODO  try to test some threshold??
           # data["PPI_PKT_LENGTHS"][i+1] < AUTH_SUCCESS_PCKT:
            return ResultAuthMethod.key
    return ResultAuthMethod.unknown

#------------------------------------------------------------------------------------------------
def detect_password(data):
    """
    Function tries to detects successfull password authentication based on threshold and response packet of minimal size.

    - data: input flows variable
    """

    #skip packet 16 and 2 SSH_MSG_SERVICE
    for i in range(data["auth_start"] + 3, min(len(data["PPI_PKT_DIRECTIONS"]) - REQ_RES_LEN, AUTH_END_THRESHOLD)):
        if data["PPI_PKT_DIRECTIONS"][i:i+REQ_RES_LEN] == REQ_RES and \
           data["PPI_PKT_LENGTHS"][i] > AUTH_PASS_MIN and \
           data["PPI_PKT_LENGTHS"][i+1] <= MAC_CATEGORIES[data["mac_category"]]["auth-success"] and \
           data["PPI_PKT_FLAGS"][i+1] % 2 != 1 and \
           len(data["PPI_PKT_FLAGS"]) > i+2 and (data["PPI_PKT_FLAGS"][i+2] & 1) != 1:        #TCP flag is not an odd number (is not FIN = 0x01)
                #EDIT: try to guess searched packet size using MAC predict
                #TODO  try to test some threshold??

            return ResultAuthMethod.password
    return ResultAuthMethod.unknown

#------------------------------------------------------------------------------------------------
def detect_traffic_type(data):
    """
    SSH protocol is quite universal tool for many purposes from an interactive shell, data transfers up to an encrypted tunnel for other applications.
    Each traffic have it's own charasteristic, which the function detects from statistical histogram data (phists plugin).

    - data: input flows variable
    """

    #get the most numerous phists bin and calculate it's ratio to the total packets count
    #total packets count is calculated from phists, because of histogram uint16 limit,
    # if flow information would be used, detection could be manupulated by really long connections
    if len(data["S_PHISTS_SIZES"]) == 0:
        #records without phists data cannot be processed, returning other.
        return ResultTrafficType.other

    #normalize histogram to percental values and select the major category
    src_size_major = data["S_PHISTS_SIZES"].index(max(data["S_PHISTS_SIZES"]))
    src_size_perc = data["S_PHISTS_SIZES"][src_size_major]/sum(data["S_PHISTS_SIZES"])
    dst_size_major = data["D_PHISTS_SIZES"].index(max(data["D_PHISTS_SIZES"]))
    dst_size_perc = data["D_PHISTS_SIZES"][dst_size_major]/sum(data["D_PHISTS_SIZES"])

    #Data transfer - upload
    if src_size_perc > TRANSFER_TRESHOLD and src_size_major > 6:
        return ResultTrafficType.upload

    #Data transfer - download
    elif dst_size_perc > TRANSFER_TRESHOLD and dst_size_major > 6:
        return ResultTrafficType.download

    #Shell terminal
    elif dst_size_major < 6 and dst_size_major > 1 and src_size_major >= 2 and src_size_major <= 3:
        return ResultTrafficType.terminal

    else:
        pass

    return ResultTrafficType.other

#------------------------------------------------------------------------------------------------
def export_result(data, alert, DEBUG):
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
    alert.AUTHENTICATION_RESULT = data["tags"]["auth"].name
    alert.AUTHENTICATION_METHOD = data["tags"]["method"].name
    alert.AUTHENTICATION_TIMING = data["tags"]["timing"].name
    alert.TRAFFIC_CATEGORY = data["tags"]["type"].name

    if DEBUG == True:
        alert.PPI_PKT_DIRECTIONS = data["PPI_PKT_DIRECTIONS"]
        alert.PPI_PKT_FLAGS = data["PPI_PKT_FLAGS"]
        alert.PPI_PKT_LENGTHS = data["PPI_PKT_LENGTHS"]
        alert.PPI_PKT_TIMES = data["PPI_PKT_TIMES"]

    return alert

#------------------------------------------------------------------------------------------------
class FlowData():
    """
    Data container for a single Unirec flow record.
    Class also provide several supporting calculating functions for common variables used accross detectors (e.g. index position of the packet with 16B size). For detector independency it could be either inside every detector (duplicate calculation) or unified in separated object as designed here.
    Class manage calculated values in a lazy way. This means class calculate requested value only if asked for and store result for later use.
    """

    AUTH_INIT_THRESHOLD = 5
    AUTH_END_THRESHOLD = 20
    # SESS_START_MIN = 11


    #--------------------------------------------------------------------------------------------
    def __init__(self, flow):
        """
        Initialize object with flow data.
        """

        for k,v in flow.getDict().items():
            setattr(self, k, v)

    #--------------------------------------------------------------------------------------------
    def __getitem__(self, key):
        """
        Overload operator [] to manage lazy loading of calculated values.
        """

        #check if searched attribute exists or try to add it
        return getattr(self, key, self.add_value(key))

    #--------------------------------------------------------------------------------------------
    def add_value(self, key):
        """
        Method is responsible for adding the requested variables if their calculation function exists. Calculation functions have the same name as the requested key prefixed with character '_'.
        """

        #check if the calculation method for the given key exists
        if hasattr(self.__class__, f'_{key}') and callable(getattr(self.__class__, f'_{key}'))
            #use getarrt to reference method and CALL IT, store result using setattr and return it as well
            setattr(self, key, getattr(self, f'_{key}')())
            return getattr(self, key)
        else:
            raise Exception(f'Unknown function to calculate requested attribute {key}.')

    #--------------------------------------------------------------------------------------------
    def _pckt_16_index(self):
        """
        Helper function find a packet of lenght 16B after ciphersuite initialization is done and before authentication start.
        The majority of traffic send this packet separately (msg SSH_NEWKEYS) once the ciphersuite keys are established (end of SSH transport layer). Thus it is the last packet without encryption and alse MAC algorithm. With this information SSH Classifier is able to determine the exact point in traffic, where the transport layer ends respectively authentication layer begins, which is usefull for futher pattern detection.
        """

        ind = 0
        if 16 in self.PPI_PKT_LENGTHS[AUTH_INIT_THRESHOLD:AUTH_END_THRESHOLD]:
            ind = self.PPI_PKT_LENGTHS[AUTH_INIT_THRESHOLD:AUTH_END_THRESHOLD].index(16) + AUTH_INIT_THRESHOLD

            #Some (server) implementation send SSH_NEWKEYS separated, means 2 packets 16B in row (oposite directions) -> shift
            #while is better than a simple if (cover more cases, e.g. duplicate packets,...)
            while len(self.PPI_PKT_LENGTHS) > val+1 and self.PPI_PKT_LENGTHS[val+1] == 16:
                val += 1

        return val

    #--------------------------------------------------------------------------------------------
    def (self):
        pass

    #--------------------------------------------------------------------------------------------
    def (self):
        pass

    #--------------------------------------------------------------------------------------------

#------------------------------------------------------------------------------------------------
class MachineLearningModel():
    """
    Universal class for exported scipy machine learning pkl.
    """

    #--------------------------------------------------------------------------------------------
    def __init__(self, path):
        """
        Initialize ML from saved pkl file

        - path: File path to the saved ML model in pkl format.
        """

        with open(path, "rb") as f:
            self.model = pickle.load(f)

    #--------------------------------------------------------------------------------------------
    def predict(self, data):
        """
        Generic function to call ML predict on given dataset.

        - data:   pandas data table with given features in columns
        """

        #convert given data table to numpy format for scipy ML predict
        #TODO try to parse better from pandas
        return self.model.predict(np.array([list(i.values()) for i in data.values]))

    #--------------------------------------------------------------------------------------------

#------------------------------------------------------------------------------------------------
class TraficTypeDetector():
    """
    Detector for SSH data traffic classicication.
    """

    #--------------------------------------------------------------------------------------------
    def __init__(self):
        pass
        #123123

    #--------------------------------------------------------------------------------------------
    def detect(self, data):
        """

        - data: input flow variable
        """
        pass

    #--------------------------------------------------------------------------------------------

#------------------------------------------------------------------------------------------------
class TimingDetector():
    """
    Detector for SSH timing during authentication..
    """

    #--------------------------------------------------------------------------------------------
    def __init__(self):
        pass

        pass

    #--------------------------------------------------------------------------------------------
    def detect(self, flow, ):
         """
        The SSH connection is usualy initialized before password/key passphrase is known and user enter credentials at runtime. This should result in a time delay for writing before authentication request is send.
        Meassuring time delays before client request we can determine if the login is interactive or automatic. Passwords and keys stored in the keychain belongs to automatic login as well.
        Function detects the client time delays in authentication phase with a simple threshold, which automatic tool should not reach until explicitly set.

        - data: input flows variable
        """

        # hop_counter = 0

        # #Limit detection only for authentication phase (if possible)
        # pckt28 = auth_layer_pckt_index(data["PPI_PKT_LENGTHS"], 28)
        # stop = min(pckt28, AUTH_END_THRESHOLD) if pckt28 > 0 else AUTH_END_THRESHOLD

        # if len(data["PPI_PKT_TIMES"]) > data["auth_start"] + 1:
        #     prev = data["PPI_PKT_TIMES"][data["auth_start"] + 1].getTimeAsFloat()
        #     for i, t in enumerate(data["PPI_PKT_TIMES"][data["auth_start"] + 1:stop], start=data["auth_start"]+1):
        #         delta = t.getTimeAsFloat() - prev
        #         prev = t.getTimeAsFloat()
        #         if data["PPI_PKT_DIRECTIONS"][i] == DIR_TO and \
        #            delta > HUMAN_AUTH_MIN_DELAY:
        #             hop_counter += 1

        # if hop_counter >= HUMAN_AUTH_HOP_THRESHOLD:
        #     return ResultAuthTiming.user
        # else:
        #     return ResultAuthTiming.auto

    #--------------------------------------------------------------------------------------------

#------------------------------------------------------------------------------------------------
class AuthenticationDetector():
    """
    Detector for SSH authentication result .
    """

    #--------------------------------------------------------------------------------------------
    def __init__(self):
        pass

    #--------------------------------------------------------------------------------------------
    def detect(self, data):
        """

        - data: input flow variable
        """
        pass

    #--------------------------------------------------------------------------------------------

#------------------------------------------------------------------------------------------------
class SSHClassifier():
    """
    Main control class for reading IFC records from pytrap and main SSH classifier logic
    """

    #--------------------------------------------------------------------------------------------
    def __init__(self, mac_pkl, single_ifc = False, stdout = False, debug = False, no_buffer = False):
        """
        Initialize class and set all given parameters.

        - mac_pkl:    path to ML pkl for MAC algorithm predicting
        - single_ifc: use ipfix one IFC merged format, instead od multiple Unirec IFC
        - stdout:     don't export result and print to stdout instead
        - debug:      append pstats info to exported results
        - no_buffer:  don't use internal buffer, can be HW consuming for ML predicting
        """

        #Prepare variable for templates and incomming flows
        self.ifc = {}
        self.single_ifc = single_ifc
        self.stdout = stdout
        self.debug = debug
        self.no_buffer = no_buffer
        self.data = {}
        self.trap = pytrap.TrapCtx()
        self.initialized = False
        self.mac_predictor = MachineLearningModel(mac_pkl)

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

        #Receive input flow record from NEMEA for each required plugin i
        #TODO change to bulk read for better performance
        for i, ifc in enumerate(self.ifc):
            rec = self.trap.recv(i)
            if len(rec) <= 1:
                raise Exception()
            self.ifc[ifc].setData(rec)

    #--------------------------------------------------------------------------------------------
    def merge_ifc(self):
        """
        Merge fetched IFC values to single dictionary for easy use
        """

        #clear from old values
        self.data = {}

        #TODO try to skip/fast convert if ipfix -x is used
        # if self.single_ifc:
        #     self.data = self.ifc["single_ifc"]

        # else:
        for ifc in self.ifc:
            for k,v in self.ifc[ifc]:
                if k not in self.data and k in SINGLE_IFC_PYTRAP_INPUT_SPECIFICATION["single_ifc"]:
                    self.data[k] = v

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
        if self.single_ifc:
            self.trap.init(sys.argv, 1, 1 if not self.stdout else 0)
            ctxs = SINGLE_IFC_PYTRAP_INPUT_SPECIFICATION
        else:
            self.trap.init(sys.argv, 3, 1 if not self.stdout else 0)
            ctxs = MULTIPLE_IFC_PYTRAP_INPUT_SPECIFICATION

        #Set required unirec format and define required input fields
        for i, (k, v) in enumerate(ctxs.items()):
            self.trap.setRequiredFmt(i, pytrap.FMT_UNIREC, v)
            self.ifc[k] = pytrap.UnirecTemplate(v)

        #Set the output field list
        self.alert = pytrap.UnirecTemplate(PYTRAP_OUTPUT_SPECIFICATION if not self.debug else PYTRAP_EXTENDED_OUTPUT_SPECIFICATION)

        #Allocate memory for the UNIREC alert template and set the data output IFC format
        if not self.stdout:
            # set the data format to the output IFC
            self.trap.setDataFmt(0, pytrap.FMT_UNIREC, PYTRAP_OUTPUT_SPECIFICATION if not self.debug else PYTRAP_EXTENDED_OUTPUT_SPECIFICATION)
            #Allocate memory for the alert, we do not have any variable fields, so no argument is needed.
            self.alert.createMessage(65000)
        else:
            #print fields header for stdout output option
            print(PYTRAP_OUTPUT_SPECIFICATION if not self.debug else PYTRAP_EXTENDED_OUTPUT_SPECIFICATION)

        self.initialized = True

    #--------------------------------------------------------------------------------------------
    def do_detection(self, records_buffer):
        """
        Main detector logic. Runs detections functions in specific order and store results

        - records_buffer: list of input data flows variable
        """

        #TODO move before saving to proccessing buffer
        #filter SSH traffic
        records_buffer['is_ssh'] = records_buffer.apply(lambda x: is_ssh(x), axis=1)
        records = records_buffer[records_buffer['is_ssh'] == True]

        if records.shape[0] == 0:   #skip if no record in buffer is valid ssh
            return

        #apply preprocess functions
        records.apply(lambda x: preprocess(x), axis=1)
        records['has16'] = records.apply(lambda x: has_16(x), axis=1)
        records['auth_start'] = records.apply(lambda x: auth_start(x), axis=1)
        features_df = records.apply(lambda x: get_mac_features(x), axis=1)

        #ML predict MAC category
        records['mac_category'] = self.mac_predictor.predict(features_df)

        #run clasification
        records["tags"] = records.apply(lambda x: self.run_detectors(x), axis=1)

        return records

    #--------------------------------------------------------------------------------------------
    def run_detectors(self, data):
        """
        Run detectors on given flow record. Return classification tags.

        - data:   flow record
        """

        tags = {'auth': ResultAuth.unknown, 'method': ResultAuthMethod.unknown, 'timing': ResultAuthTiming.unknown, 'type': ResultTrafficType.unknown}

        #Detect publickey authentication with precheck
        tags['method'] = detect_key(data)

        #Detect authentication result (skip if key was detected)
        if tags['method'] == ResultAuthMethod.unknown:
            tags['auth'] = detect_auth_fail(data)

        #Detect timing, even for failed authentication
        tags['timing'] = detect_user_auth(data)

        if tags['method'] != ResultAuthMethod.unknown:
            tags['auth'] = ResultAuth.auth_ok

        #No reason to process other detections for failed authentication
        if tags['auth'] != ResultAuth.fail:
            if tags['method'] == ResultAuthMethod.unknown:
                tags['method'] = detect_key_without_precheck(data)

                if tags['method'] == ResultAuthMethod.unknown:
                    tags['method'] = detect_password(data)

                if tags['method'] != ResultAuthMethod.unknown:
                    tags['auth'] = ResultAuth.auth_ok

            #Try to detect traffic type, even for unknown authentication method
            tags['type'] = detect_traffic_type(data)
        else:
            pass

        return tags

    #--------------------------------------------------------------------------------------------
    def main(self):
        """
        This only method should be called after creating SSHClassifier object.
        Use it as a entry point, it initialize all pytrap requirements, manage records reading in loop, buffering and finally run classification.

        """

        self.initialize()

        #Main detector loop
        running = True
        records_buffer = pd.DataFrame()

        while running:
            try:
                self.fetch_record()

            except pytrap.FormatChanged as e:
                fmttype, inputspec = self.trap.getDataFmt(0)
                if self.single_ifc:
                    self.ifc["single_ifc"] = pytrap.UnirecTemplate(inputspec)
                    edata = e.data
                    if len(edata) <= 1:
                        raise Exception()
                    self.ifc["single_ifc"].setData(edata)
                else:
                    #TODO check if this case can happen
                    exit(10)

            except Exception as e:
                running = False
                print(e)
                continue

            # merge received IFC records to dictionary
            self.merge_ifc()

            #append received records to proccesing buffer
            # if records_buffer.shape[0] < BUFFER_CNT or not self.no_buffer:
            records_buffer = records_buffer.append(self.data, ignore_index=True)

            # start detection for all records in buffer if it contains at least BUFFER_CNT (or no_buffer is set)
            if records_buffer.shape[0] >= BUFFER_CNT or self.no_buffer:
                results = self.do_detection(records_buffer)
                if results is not None:
                    if not self.stdout:
                        #print(len(results))
                        for row in results.to_dict(orient='records'):
                            self.alert = export_result(row, self.alert, self.debug)
                            self.trap.send(self.alert.getData(), 0)
                    else:
                        pass
                        # print(results["tags"])

                #clean buffer after processing
                records_buffer = pd.DataFrame()
            else:
                #there are not enough records in the buffer
                pass

# ------------------------------------------------------------------------------------------------
def main():

   #Explicit parse options for single IFC from ipfix collector or NEMEA multiple IFC
    parser = argparse.ArgumentParser(prog='NEMEA SSH detector')
    parser.add_argument('-x', '--ipfix', action='store_true', help='Single input IFC format from IPFIX collector')
    parser.add_argument('--stdout', action='store_true', help='Write output to stdout instead of Unirec')
    parser.add_argument('--debug', action='store_true', help='Add pstats info into the output IFC')
    parser.add_argument('--mac-classifier-path', default=None, help='Path to the python pkl object with MAC classifier')
    parser.add_argument('--no-buffer', help='Do not use proccesing buffer on incomming records. (could be more HW consuming due MAC ML predict)', action='store_true')
    args, unknown = parser.parse_known_args()

    ssh_classifier = SSHClassifier(args.mac_classifier_path, args.ipfix, args.stdout, args.debug)
    ssh_classifier.main()

#------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    main()
