# (C) 2023 CESNET z.s.p.o. Prague, Czech Republic
# (C) 2023 FIT CTU in Prague, Czech Republic
# (C) 2023 FIT VUT in Brno, Czech Republic

import sys
import numpy as np
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

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

        return self.model.predict(data)

    #--------------------------------------------------------------------------------------------
