# (C) 2023 CESNET z.s.p.o. Prague, Czech Republic
# (C) 2023 FIT CTU in Prague, Czech Republic
# (C) 2023 FIT VUT in Brno, Czech Republic


import pandas as pd
import numpy as np
from flow_data import DIR_TO, DIR_FROM, ResultAuthTiming, FlowData


#------------------------------------------------------------------------------------------------
class TimingDetector():
    """
    Detector for SSH timing during authentication.
    """

    #Thresholds
    HUMAN_AUTH_MIN_DELAY = 1 #seconds
    HUMAN_AUTH_HOP_THRESHOLD = 1

    #-------------------------------------------------------------------------------------------- 
    def __init__(self):
        pass

    #--------------------------------------------------------------------------------------------
    def detect(self, records):
        """
        The SSH connection is usualy initialized before password/key passphrase is known and user enter credentials at runtime. This should result in a time delay for writing before authentication request is send.
        Meassuring time delays before client request we can determine if the login is interactive or automatic. Passwords and keys stored in the keychain belongs to automatic login as well.
        Function detects the client time delays in authentication phase with a simple threshold, which automatic tool should not reach until explicitly set.

        Args:
            FlowData

        Returns:
            pandas DataFrame containing ResultAuthTiming.[user/auto]
        """

        #prepare df with times in assumed authentication layer and directions
        timing_df = pd.DataFrame()
        timing_df['PPI_PKT_TIMES'] = records.data.apply(lambda row: row['PPI_PKT_TIMES'][row['auth_start']:row['auth_end']], axis=1)
        timing_df['PPI_PKT_DIRECTIONS'] = records.data.apply(lambda row: row['PPI_PKT_DIRECTIONS'][row['auth_start']:row['auth_end']], axis=1)
        
        #calculate time differences between times 
        time_difference = timing_df.apply(lambda row: [ (row['PPI_PKT_TIMES'][i].getTimeAsFloat() - row['PPI_PKT_TIMES'][i-1].getTimeAsFloat()) if row['PPI_PKT_DIRECTIONS'][i] == DIR_TO else 0 for i in range (1,len(row['PPI_PKT_TIMES']))], axis=1)

        #since using only 1 time hop, use max to get true/false value
        return pd.DataFrame(np.where(time_difference.apply(lambda x: max(x, default=0)) > TimingDetector.HUMAN_AUTH_MIN_DELAY, ResultAuthTiming.user, ResultAuthTiming.auto))
    
        #CHANGE_NOTE: previous version returns ResultAuthTiming.unknown for short connection ... #TODO it will probably crash on missing data (fix n/a)
        
        
        # time_difference = timing_df.apply(lambda x: [(x[i] - x[i-1]) for i in range(1,len(x))])
        # time_difference = timing_df.apply(lambda x: [(x[i] - x[i-1]) if directions.loc[x.name[i]] == DIR_TO else 0 for i in range(1,len(x))])
        # time_difference.apply(lambda x: x>TimingDetector.HUMAN_AUTH_MIN_DELAY and directions.loc[x.name[] for i in x)
        # times[(max_time_difference >= TimingDetector.HUMAN_AUTH_MIN_DELAY)]
        # time_difference[time_difference.apply(max) > TimingDetector.HUMAN_AUTH_MIN_DELAY].index



        # prev = flow.PPI_PKT_TIMES[flow.auth_start].getTimeAsFloat()
        # #Limit detection only for authentication phase (if possible), keep (shift) enumerate index same as full flow
        # for i, t in enumerate(flow.PPI_PKT_TIMES[flow.auth_start:flow.auth_end], start=flow.auth_start):
        #     #check direction (client -> server)
        #     if flow.PPI_PKT_DIRECTIONS[i] == DIR_TO and \
        #         (t.getTimeAsFloat() - prev) > TimingDetector.HUMAN_AUTH_MIN_DELAY:
        #         hop_counter += 1
        #     prev = t.getTimeAsFloat()

        # if hop_counter >= TimingDetector.HUMAN_AUTH_HOP_THRESHOLD:
        #     return ResultAuthTiming.user
        # elif i > 0:
        #     #previous loop was proccessed with at least some iterations
        #     return ResultAuthTiming.auto
        # else:
        #     #authentication layer was not found (e.g. too short connection, non-standard behaviour, one way directions,...)
        #     return ResultAuthTiming.unknown

    #--------------------------------------------------------------------------------------------
