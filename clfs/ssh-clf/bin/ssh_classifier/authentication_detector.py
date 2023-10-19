# (C) 2023 CESNET z.s.p.o. Prague, Czech Republic
# (C) 2023 FIT CTU in Prague, Czech Republic
# (C) 2023 FIT VUT in Brno, Czech Republic

import numpy as np
import pandas as pd

from flow_data import DIR_TO, DIR_FROM, ResultAuth, ResultAuthMethod, FlowData


#------------------------------------------------------------------------------------------------
class AuthenticationDetector():
    """
    Detector for SSH authentication result.
    """

    #Thresholds
    AUTH_KEY_DIR_PATTERN = [DIR_TO, DIR_FROM, DIR_TO, DIR_FROM]
    AUTH_KEY_DIR_PATTERN_LEN = 4
    AUTH_PASS_DIR_PATTERN = [DIR_TO, DIR_FROM]
    AUTH_PASS_DIR_PATTERN_LEN = 2
    AUTH_KEY_MIN = 256
    AUTH_PASS_MIN = 80
    AUTH_SUCCESS_PCKT = 50  #long MAC can dramatically change success packet size (e.g. for 512b MAC 84 bytes, which is above detection sensitivity)
    CHACHA_POLY_AUTH_SIZE = 28
    MIN_PCKT_TO_AUTH = 5    #minimal packet count from authentication layer start to success authentication
    MIN_PCKT_AFTER_AUTH = 3
    AUTH_KEY_COEF = 0.65
    AUTH_RESPONSE_SIZE_DIFF = 0.2
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

    #--------------------------------------------------------------------------------------------
    def __init__(self, mac_predictor = False):
        self.mac_predictor = mac_predictor

    #--------------------------------------------------------------------------------------------
    def get_success_packet_size(self, mac_category):
        """

        """

        if self.mac_predictor and mac_category in AuthenticationDetector.MAC_CATEGORIES:
            return AuthenticationDetector.MAC_CATEGORIES[mac_category]["auth-success"]

        else:
            AuthenticationDetector.AUTH_SUCCESS_PCKT

    #--------------------------------------------------------------------------------------------
    def detect_key(self, records):
        """
        Function detects key authentication with public key precheck based on directions and packet lenghts pattern.
        SSH authentication using public key and signature is designed in following pattern:
        1. client sends authentication precheck (SSH_MSG_USERAUTH_REQUEST) with it's public key and without signature to ensure that server know and accept this public key (optional)
        2. server either refuses public key (SSH_MSG_USERAUTH_FAILURE) or accept (SSH_MSG_USERAUTH_PK_OK) including received public key in the answer, which reflects on response packet size
        3. client sends authentication request again accompanied by a signature (using correct private key). The signature is next to the public key the largest element in the message. Adding signature makes the request size almost double of previous precheck.
        4. server verify signatures and either allow (SSH_MSG_USERAUTH_SUCCESS) or deny (SSH_MSG_USERAUTH_FAILURE) access. Detection can use predicted MAC algorithm to calculate the exact packet size of SSH_MSG_USERAUTH_SUCCESS message.

        - data: input flows variable
        """

        local = pd.DataFrame(index=records.index)
        local['PPI_PKT_LENGTHS'] = records['PPI_PKT_LENGTHS']
        local['mac_category'] = records['mac_category']

        local['directions_match'] = records.apply(lambda row: row['PPI_PKT_DIRECTIONS'][row['auth_start']+2:row['auth_end']], axis=1).map(lambda x: np.argmax(np.array([ i if (x[i:i+AuthenticationDetector.AUTH_KEY_DIR_PATTERN_LEN] == AuthenticationDetector.AUTH_KEY_DIR_PATTERN) else np.nan for i in range(0, len(x) - AuthenticationDetector.AUTH_KEY_DIR_PATTERN_LEN)])>0) if len(x) > AuthenticationDetector.AUTH_KEY_DIR_PATTERN_LEN else 0)

        local['return'] = np.nan
        local['return'] = local[local['directions_match'] > 0].apply(lambda row: True if (row['PPI_PKT_LENGTHS'][row['directions_match']+1] > row['PPI_PKT_LENGTHS'][row['directions_match']] * AuthenticationDetector.AUTH_KEY_COEF) and (row['PPI_PKT_LENGTHS'][row['directions_match']+1] < row['PPI_PKT_LENGTHS'][row['directions_match']]) and (row['PPI_PKT_LENGTHS'][row['directions_match']+2] > row['PPI_PKT_LENGTHS'][row['directions_match']] * 2 * AuthenticationDetector.AUTH_KEY_COEF) and (row['PPI_PKT_LENGTHS'][row['directions_match']+3] <= self.get_success_packet_size(row['mac_category'])) else False, axis=1)
        return local['return']
            
    #--------------------------------------------------------------------------------------------
    def detect_chacha(self, records):
        """
        Packet size 28 in the SSH authentication layer use chacha-poly cipher, which should be the minimal packet length (only SSH message code). For authentication scope it means accepted login. Other ciphersuite combinations have different block size and MAC size and due to padding, it's can colaps with other messages.
        """

        local = pd.DataFrame(index=records.index)
        local['return'] = np.nan

        local['return'] = records.apply(lambda row: True if \
                (AuthenticationDetector.CHACHA_POLY_AUTH_SIZE in row['PPI_PKT_LENGTHS'][row['auth_start']:row['auth_end']]) and \
                (row['PPI_PKT_DIRECTIONS'][row['PPI_PKT_LENGTHS'][row['auth_start']:row['auth_end']].index(AuthenticationDetector.CHACHA_POLY_AUTH_SIZE)] == DIR_FROM) else False, axis=1)
        return local['return']

    #--------------------------------------------------------------------------------------------
    def detect_auth_fail(self, records):
        """
        Function exclude flows where authentication cannot be completed (e.g. short communication).

        - data: input flows variable
        """

        return pd.Series(np.where((records.packet_count >= FlowData.SESS_START_MIN) & (records.auth_start + AuthenticationDetector.MIN_PCKT_TO_AUTH < records.packet_count) & (records.PPI_PKT_DIRECTIONS.map(lambda x: x.count(DIR_TO)) >= records.auth_start + 3) & (records.PPI_PKT_DIRECTIONS.map(lambda x: x.count(DIR_FROM)) >= records.auth_start + 3), True, False))

        # if flow.packet_count < FlowData.SESS_START_MIN:
        #     return ResultAuth.fail

        # if flow.auth_start + AuthenticationDetector.MIN_PCKT_TO_AUTH >= flow.packet_count or \
        #    flow.PPI_PKT_DIRECTIONS[flow.auth_start+1:].count(DIR_TO) < 3 or \
        #    flow.PPI_PKT_DIRECTIONS[flow.auth_start+1:].count(DIR_FROM) < 3:
            # return ResultAuth.fail

        # else:
        #     return ResultAuth.unknown

    #--------------------------------------------------------------------------------------------
    def detect_repeating(self, flow):
        """
        Function detects repeated authentication tries and it's results, based on average response size. Client is offten allowed to try login several times in one connection. In repeated failing login pattern we should see the same server response (client request could slightly vary, e.g. +/- block size, depends on password lenght). Meassuring server response sizes (min, max, avg) we can confirm login failure if repeating if found until communication end or deduce login success if smaller response is found.

        - data: input flows variable
        """

        i = flow.auth_start + 2 #skip 2x SERVICE_REQUEST
        sum_dst = 0
        cnt_dst = 0
        max_dst = 0
        min_dst = 0

        #Calculate sum of responses in selected packets
        while i < flow.packet_count and \
              flow.PPI_PKT_LENGTHS[i] > self.get_success_packet_size(flow.mac_category):
            if flow.PPI_PKT_DIRECTIONS[i] == DIR_FROM:
                sum_dst += flow.PPI_PKT_LENGTHS[i]
                cnt_dst += 1
                max_dst = max_dst if max_dst > flow.PPI_PKT_LENGTHS[i] else flow.PPI_PKT_LENGTHS[i]
                min_dst = min_dst if min_dst < flow.PPI_PKT_LENGTHS[i] else flow.PPI_PKT_LENGTHS[i]
            i += 1

        #cycle stoped before list end, (small packet was found -> probably authenticated)
        if i < flow.packet_count - AuthenticationDetector.MIN_PCKT_AFTER_AUTH:
            return ResultAuth.auth_ok

        #Detect similar size in server responses (based on average difference)          #TODO avg_dst -> sum_dst
        if cnt_dst > 0:
            if max_dst - (sum_dst/cnt_dst) < sum_dst * AuthenticationDetector.AUTH_RESPONSE_SIZE_DIFF or \
               (sum_dst/cnt_dst) - min_dst < sum_dst * AuthenticationDetector.AUTH_RESPONSE_SIZE_DIFF:
                return ResultAuth.fail

        return ResultAuth.unknown

    #--------------------------------------------------------------------------------------------
    def detect_key_without_precheck(self, records):
        """
        As mention in detect_key, the public key precheck is optional and this step has no result in authentication result.
        Similar to password detection, function tries to detects key authentication without precheck based on threshold and response packet of minimal size. In contrast with password, the send key is usually much longer (ECC keys are much shorter, so the can look like very long password).

        #TODO to increase precision there could be possibility to guess aprox. AUTH_KEY_MIN for each public key length (but username is also sent along with the key)

        - data: input flows variable
        """

        local = pd.DataFrame(index=records.index)
        local['PPI_PKT_LENGTHS'] = records['PPI_PKT_LENGTHS']
        local['mac_category'] = records['mac_category'] 
        local['PPI_PKT_FLAGS'] = records['PPI_PKT_FLAGS']
        local['return'] = np.nan

        local['directions_match'] = records.apply(lambda row: row['PPI_PKT_DIRECTIONS'][row['auth_start']+2:row['auth_end']], axis=1).map(lambda x: np.argmax(np.array([ i if (x[i:i+AuthenticationDetector.AUTH_PASS_DIR_PATTERN_LEN] == AuthenticationDetector.AUTH_PASS_DIR_PATTERN) else np.nan for i in range(0, len(x) - AuthenticationDetector.AUTH_PASS_DIR_PATTERN_LEN)])>0) if len(x) > AuthenticationDetector.AUTH_PASS_DIR_PATTERN_LEN else 0)
        
        local['return'] = local[local['directions_match'] > 0].apply(lambda row: True if (row['PPI_PKT_LENGTHS'][row['directions_match']] > AuthenticationDetector.AUTH_KEY_MIN) and (row['PPI_PKT_LENGTHS'][row['directions_match']+1] <= self.get_success_packet_size(row['mac_category'])) and (row['PPI_PKT_FLAGS'][row['directions_match']+1] & 1 != 1) and (row['PPI_PKT_FLAGS'][row['directions_match']+2] & 1 != 1) else False, axis=1)

        return local['return']

    #--------------------------------------------------------------------------------------------
    def detect_password(self, records):
        """
        Function tries to detects successfull password authentication based on threshold and response packet of minimal size.

        - data: input flows variable
        """

        local = pd.DataFrame(index=records.index)
        local['PPI_PKT_LENGTHS'] = records['PPI_PKT_LENGTHS']
        local['mac_category'] = records['mac_category'] 
        local['PPI_PKT_FLAGS'] = records['PPI_PKT_FLAGS']
        local['return'] = np.nan

        local['directions_match'] = records.apply(lambda row: row['PPI_PKT_DIRECTIONS'][row['auth_start']+2:row['auth_end']], axis=1).map(lambda x: np.argmax(np.array([ i if (x[i:i+AuthenticationDetector.AUTH_PASS_DIR_PATTERN_LEN] == AuthenticationDetector.AUTH_PASS_DIR_PATTERN) else np.nan for i in range(0, len(x) - AuthenticationDetector.AUTH_PASS_DIR_PATTERN_LEN)])>0) if len(x) > AuthenticationDetector.AUTH_PASS_DIR_PATTERN_LEN else 0)
        
        local['return'] = local[local['directions_match'] > 0].apply(lambda row: True if (row['PPI_PKT_LENGTHS'][row['directions_match']] > AuthenticationDetector.AUTH_PASS_MIN) and (row['PPI_PKT_LENGTHS'][row['directions_match']+1] <= self.get_success_packet_size(row['mac_category'])) and (row['PPI_PKT_FLAGS'][row['directions_match']+1] & 1 != 1) and (row['PPI_PKT_FLAGS'][row['directions_match']+2] & 1 != 1) else np.nan, axis=1)

        return local['return']

    #--------------------------------------------------------------------------------------------
    def detect(self, records):
        """

            #TODO
        
        """

        #ensure auth_start and auth_end in records
        records.auth_start
        records.auth_end

        authentication = pd.DataFrame()

        authentication['auth_fail_continue'] = self.detect_auth_fail(records)

        if len(authentication[authentication['auth_fail_continue'] == True]) > 0:

            authentication['detect_key'] = self.detect_key(records.data[authentication['auth_fail_continue'] == True])
            authentication['chacha'] = self.detect_chacha(records.data[(authentication['auth_fail_continue'] == True) & (authentication['detect_key'] != True)]) #False should have only processed rows (other np.nan)
            authentication['precheck_key'] = self.detect_key_without_precheck(records.data[(authentication['auth_fail_continue'] == True) & ((authentication['chacha'] != True) | (authentication['detect_key'] != True))])
            
            authentication['method'] = authentication[(authentication['detect_key'] == True) | (authentication['chacha'] == True) | (authentication['precheck_key'] == True)].apply(lambda x: ResultAuthMethod.key)

            authentication['password'] = self.detect_password(records.data[(authentication['auth_fail_continue'] == True) & (authentication['method'] != ResultAuthMethod.key)]).replace(True, ResultAuthMethod.password)
    
            authentication['method'] = authentication['method'].fillna(authentication['password'])
    
            authentication['result'] = np.where(authentication['method'].notna(), ResultAuth.auth_ok, ResultAuth.fail)
    
            authentication['method'] = authentication['method'].fillna(ResultAuthMethod.unknown)
    
        else:
            authentication['result'] = ResultAuth.fail
            authentication['method'] = ResultAuthMethod.unknown
        
        return authentication[['result', 'method']]


        #first exclude all flows where authentication cannot be completed
        # res_auth, res_method = ResultAuth.unknown, ResultAuthMethod.unknown

        # res_auth = self.detect_auth_fail(flow)

        # if res_auth == ResultAuth.unknown:
            # res_auth, res_method = self.detect_key(flow)

            #if key was not detected, try to detect chacha-poly auth confirmation
            # if res_method == ResultAuthMethod.unknown:
            #     res_auth, res_method = self.detect_key_without_precheck(flow)

                # if res_method == ResultAuthMethod.unknown:
                #     res_auth, res_method = self.detect_password(flow)

                    # if res_method == ResultAuthMethod.unknown:
                    #     res_auth = self.detect_chacha(flow)

                        # if res_auth == ResultAuth.unknown:
                        #     res_auth = self.detect_repeating(flow)          # TODO ????

        # TODO try to mark/remember recognized auth success/fail packet index for better following detections (e.g. limit timing only to auth layer with more precision than simple threshold)

        # return res_auth, res_method

    #--------------------------------------------------------------------------------------------
