import numpy as np
import pandas as pd

from flow_data import ResultTrafficType, FlowData

#------------------------------------------------------------------------------------------------
class TrafficTypeDetector():
    """
    Detector for SSH data traffic classicication.
    """

    TRANSFER_TRESHOLD = 0.7

    #--------------------------------------------------------------------------------------------
    def __init__(self):
        pass

    #--------------------------------------------------------------------------------------------
    # def detect_terminal(self, records):
    #     """
    #     #TODO
    #     shell terminal shows quite small packet in interactive typing (client send key character, server respond, client show key character on terminal).

    #     """

        # #Shell terminal
        # if flow.hist_dst_size_major < 6 and \
        #    flow.hist_dst_size_major > 1 and \
        #    flow.hist_src_size_major >= 2 and \
        #    flow.hist_src_size_major <= 3:
        #     return ResultTrafficType.terminal

        # else:
        #     return ResultTrafficType.other

    #--------------------------------------------------------------------------------------------
    # def detect_transfer(self, records):
    #     """
    #         Uploading and downloading data results in high number of large packet (MTU).
    #         Function gets the most frequent phists bin and calculate it's ratio to the packets count (sum is used instead of total flow packet count due to histogram uint limits).
    #     """

        # #Data transfer - upload (1024+ B packets at bin index 7)
        # if flow.hist_src_size_major > 6 and \
        #    flow.hist_src_size_perc > TrafficTypeDetector.TRANSFER_TRESHOLD:
        #     return ResultTrafficType.upload

        # #Data transfer - download (1024+ B packets at bin index 7)
        # elif flow.hist_dst_size_major > 6 and \
        #      flow.hist_dst_size_perc > TrafficTypeDetector.TRANSFER_TRESHOLD:
        #     return ResultTrafficType.download

        # else:
        #     return ResultTrafficType.other

    #--------------------------------------------------------------------------------------------
    def detect(self, records, authorized_records_idx):
        """
        SSH protocol is quite universal tool for many purposes from an interactive shell, data transfers up to an encrypted tunnel for other applications.
        Each traffic have it's own charasteristic, which the function detects from statistical histogram data (phists plugin).

        Args:
            FlowData

        Returns:
            pandas DataFrame containing column with ResultTrafficType
        """

        transfer = pd.DataFrame()

        """
        Uploading and downloading data results in high number of large packet (MTU).
        Function gets the most frequent phists bin and calculate it's ratio to the packets count (sum is used instead of total flow packet count due to histogram uint limits).
        """
        #upload
        transfer['upload'] = np.where((records.hist_src_size_major > 6) & (records.hist_src_size_perc > TrafficTypeDetector.TRANSFER_TRESHOLD), ResultTrafficType.upload, np.nan)
        #download
        transfer['download'] = np.where((records.hist_dst_size_major > 6) & (records.hist_dst_size_perc > TrafficTypeDetector.TRANSFER_TRESHOLD), ResultTrafficType.download, np.nan)
        

        """
        shell terminal shows quite small packet in interactive typing (client send key character, server respond, client show key character on terminal).
        """
        #terminal
        transfer['terminal'] = np.where((records.hist_dst_size_major < 6) & (records.hist_dst_size_major > 1) & (records.hist_src_size_major >= 2) & (records.hist_src_size_major <= 3), ResultTrafficType.terminal, np.nan)

        #concat all detected types in authorized flows only (apply this method to other flow e.g. scan could lead to high false positives due to minimal packet count in traffic) 
        transfer['traffic_type'] = np.nan
        transfer['traffic_type'] = transfer['traffic_type'].fillna(transfer['upload'].iloc[authorized_records_idx])
        transfer['traffic_type'] = transfer['traffic_type'].fillna(transfer['download'].iloc[authorized_records_idx])
        transfer['traffic_type'] = transfer['traffic_type'].fillna(transfer['terminal'].iloc[authorized_records_idx])
        transfer['traffic_type'] = transfer['traffic_type'].fillna(ResultTrafficType.other)
        
        return transfer['traffic_type']
    
    #--------------------------------------------------------------------------------------------
