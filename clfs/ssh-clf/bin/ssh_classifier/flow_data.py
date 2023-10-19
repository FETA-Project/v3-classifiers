# (C) 2023 CESNET z.s.p.o. Prague, Czech Republic
# (C) 2023 FIT CTU in Prague, Czech Republic
# (C) 2023 FIT VUT in Brno, Czech Republic

import numpy as np
import pandas as pd
from enum import Enum
from enum import auto as auto_id
import pandas as pd

# Constants
#------------------------------------------------------------------------------------------------
DIR_TO = 1
DIR_FROM = -1

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

#------------------------------------------------------------------------------------------------
class FlowData():
    """
    Data container for a single Unirec flow record.
    Class also provide several supporting calculating functions for common variables used accross detectors (e.g. index position of the packet with 16B size). For detector independency it could be either inside every detector (duplicate calculation) or unified in separated object as designed here.
    Class manage calculated values in a lazy way. This means class calculate requested value only if asked for and store result for later use.
    """

    #Constants
    FILTER_SSH_string = bytearray("SSH", 'utf-8')
    FILTER_MIN_BYTES_ONE_DIR = 60
    FILTER_MIN_PACKETS_ONE_DIR = 6



    #Thresholds
    AUTH_INIT_THRESHOLD = 5
    AUTH_END_THRESHOLD = 20
    SESS_START_MIN = 11
    SSH_USERAUTH_VALUES = {32, 36, 40, 44, 48, 52, 56, 60, 64, 68, 88, 92, 96, 100}
    PRE_AUTH_DIR_PATTERN = [DIR_TO, DIR_FROM, DIR_TO, DIR_FROM] #SSH_MSG_SERVICE 2x
    PRE_AUTH_DIR_PATTERN_LEN = 4

    #--------------------------------------------------------------------------------------------
    def __init__(self, bulkRecords):
        """
        Initialize object with flow data.
        
        Expecting list of dictionaries.
        """

        if len(bulkRecords) > 0:
            #filter out non-SSH traffic and save as pandas DataFrame
            self.data = FlowData.filter_ssh(pd.DataFrame(bulkRecords))
            self.data.reset_index(inplace=True, drop=True)

        else:
            self.data = pd.DataFrame()

    #--------------------------------------------------------------------------------------------
    def len(self):
        return self.data.shape[0]

    #--------------------------------------------------------------------------------------------
    @staticmethod
    def filter_ssh(df):
        """
        Filter valid SSH traffic (bidirectional) based on constant parameters in FlowData class variables. Function check if the flow record is valid SSH traffic, connection contains enough data packet in both directions and START with client to server direction.

        Args:
            df: pandas DataFrame with Unirec flows records values in rows

        Returns:
            filtered pandas DataFrame containing valid bidirectional SSH traffic
        """
        
        return df[(df["IDP_CONTENT"].str.startswith(FlowData.FILTER_SSH_string)) & \
                    (df["IDP_CONTENT_REV"].str.startswith(FlowData.FILTER_SSH_string)) & \
                    (df["BYTES"] >= FlowData.FILTER_MIN_BYTES_ONE_DIR) & \
                    (df["BYTES_REV"] >= FlowData.FILTER_MIN_BYTES_ONE_DIR) & \
                    (df["PACKETS"] >= FlowData.FILTER_MIN_PACKETS_ONE_DIR) & \
                    (df["PACKETS_REV"] >= FlowData.FILTER_MIN_PACKETS_ONE_DIR) & \
                    (df["PPI_PKT_DIRECTIONS"].str[0] == DIR_TO)]

    #--------------------------------------------------------------------------------------------
    def __getattr__(self, key):
        """
        Overload attribute access implicit getter to manage "lazy loading" of calculated values.

        Args:
            key: requested flow attribute
        Returns:
            pandas Series column with requested flow attribute
        """

        #check if searched attribute exists or try to add it
        if key in self.data:
            return self.data[key]
        elif hasattr(self.__class__, f'_{key}') and callable(getattr(self.__class__, f'_{key}')):
            #get reference to function by getattr and CALL it as function
            self.data[key] = getattr(self, f'_{key}')(self)
            return self.data[key]
        else:
            raise Exception(f'Unknown function to calculate requested flow attribute {key}.')

    #--------------------------------------------------------------------------------------------
    @staticmethod
    def _pckt_16_index(flowdata):
        """
        Helper function find a packet of lenght 16B (after ciphersuite initialization is done and before authentication start).
        The majority of traffic send this packet separately (msg SSH_NEWKEYS) once the ciphersuite keys are established (end of SSH transport layer). Thus it is the last packet without encryption and also MAC algorithm. With this information SSH Classifier is able to determine the exact point in traffic, where the transport layer ends respectively authentication layer begins, which is usefull for futher pattern recognition.
        
        Returns:
            pandas Series column with the position indices of the LAST 16B packet
        """

        #Due to performance use last 16B packet index - implemented as find first in reversed list, instead of first find 16B packet and look further until non-16B packet size was found (which is not exactly the same behaviour, and if causing errors it will have to change back)
        return flowdata.PPI_PKT_LENGTHS.map(lambda row: (len(row) - row[::-1].index(16) - 1) if 16 in row else 0)

    #--------------------------------------------------------------------------------------------
    @staticmethod
    def _packet_count(flowdata):
        """
        Returns the minimal number of packets in pstats array variables.

        Args:
            pandas DataFrame (should have columns: ["PPI_PKT_LENGTHS"])
        
        Returns:
            pandas Series with lengths of each record
        """


        df = flowdata.data
        #if failing, try to do min from "PPI_PKT_LENGTHS", "PPI_PKT_DIRECTIONS", "PPI_PKT_TIMES"
        return df["PPI_PKT_LENGTHS"].map(len)

    #--------------------------------------------------------------------------------------------
    @staticmethod
    def auth_start_pattern(flow):
        """

        """


        for i in range(FlowData.AUTH_INIT_THRESHOLD, len(flow['PPI_PKT_LENGTHS']) - FlowData.PRE_AUTH_DIR_PATTERN_LEN):
            if flow['PPI_PKT_LENGTHS'][i] == flow['PPI_PKT_LENGTHS'][i+1] and \
               flow['PPI_PKT_DIRECTIONS'][i] != flow['PPI_PKT_DIRECTIONS'][i+1] and \
               flow['PPI_PKT_LENGTHS'][i] in FlowData.SSH_USERAUTH_VALUES:
    
                #guess auth start from 'ssh-userauth' SSH_MSG_SERVICE_REQUEST (2 packets, same size, oposite directions, typical lenght - based on cipher/mac options)
                return i
    
            elif flow['PPI_PKT_DIRECTIONS'][i:i + FlowData.PRE_AUTH_DIR_PATTERN_LEN] == FlowData.PRE_AUTH_DIR_PATTERN:
                #guess based on direction pattern (NEWKEYS, 2x SSH_MSG_SERVICE_REQUEST, 2x ..)
                return i
        return 0

    #--------------------------------------------------------------------------------------------
    @staticmethod
    def _auth_start(flowdata):
        """
        Function returns the position of the authentication layer begining. If 16B packet is found, function returns it's position. If not, function tries to determine the position based on the packet length and direction pattern.
        Pattern should consist of client request (SSH_MSG_SERVICE_REQUEST) and server response of the same size (Different end/MAC algorithms are not supported). The packet size is also checked for valid values.
        SSH protocol uses message padding. Because SSH_MSG_SERVICE_REQUEST contain only static data, combined with the possible MAC algoritms we can define all valid packet sizes for this request.

        Args:
        - data: input flows variable
        """
        
        tmp = flowdata.pckt_16_index.map(lambda x: x+1 if x > 0 else np.nan)
        if tmp.isnull().any():
            tmp = tmp.fillna(flowdata.data[tmp.isna()].apply(lambda x: FlowData.auth_start_pattern(x) if len(x['PPI_PKT_LENGTHS']) > FlowData.SESS_START_MIN else 0, axis=1))
        return tmp.astype('int')


    #--------------------------------------------------------------------------------------------
    @staticmethod
    def _auth_end(flowdata):
        """
        Returns min of flow packet_count and AUTH_END_THRESHOLD.
        """

        return np.minimum(flowdata.packet_count, FlowData.AUTH_END_THRESHOLD)

    #--------------------------------------------------------------------------------------------
    def _mac_category(self):
        """
        Dummy method to supress exception on access. Mac category is not calculated, but can be set up in __init__ or manualy.
        """

        return None

    #--------------------------------------------------------------------------------------------
    @staticmethod
    def _hist_src_size_major(flowdata):
        """
        Get the indices of the most frequent hist source size bin         

        Args:
            pandas DataFrame (should have columns: ["S_PHISTS_SIZES"])

        Returns:
            pandas Series with indices of the most frequent hist source size bin
        """
    
        #get most frequent hist bin
        return flowdata.S_PHISTS_SIZES.map(lambda x: x.index(max(x)))

    #--------------------------------------------------------------------------------------------
    @staticmethod
    def _hist_src_size_perc(flowdata):
        """
        Get the normalized percental value of the major hist source size bin         

        Args:
            pandas DataFrame (should have columns: ["S_PHISTS_SIZES"])

        Returns:
            pandas Series with normalized (percental) values of the major hist source size bin
        """

        #normalize the major histogram bin to percental values
        return flowdata.S_PHISTS_SIZES.map(lambda x: max(x) / sum(x))
    
    #--------------------------------------------------------------------------------------------
    @staticmethod
    def _hist_dst_size_major(flowdata):
        """
        Get the indices of the most frequent hist destination size bin         

        Args:
            pandas DataFrame (should have columns: ["D_PHISTS_SIZES"])

        Returns:
            pandas Series with indices of the most frequent hist destination size bin
        """
    
        #get most frequent hist bin
        return flowdata.D_PHISTS_SIZES.map(lambda x: x.index(max(x)))

    #--------------------------------------------------------------------------------------------
    @staticmethod
    def _hist_dst_size_perc(flowdata):
        """
        Get the normalized percental value of the major hist destination size bin         

        Args:
            pandas DataFrame (should have columns: ["D_PHISTS_SIZES"])

        Returns:
            pandas Series with normalized (percental) values of the major hist destination size bin
        """

        #normalize the major histogram bin to percental values
        return flowdata.D_PHISTS_SIZES.map(lambda x: max(x) / sum(x))

    #--------------------------------------------------------------------------------------------
