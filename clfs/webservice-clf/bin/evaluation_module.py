#!/usr/bin/env python3.11

# (C) 2023 CESNET z.s.p.o. Prague, Czech Republic
# (C) 2023 FIT CTU in Prague, Czech Republic
# (C) 2023 FIT VUT in Brno, Czech Republic

import argparse
import os
import sys
import threading
import warnings
from functools import partial
from importlib.metadata import version
from threading import Condition, Lock, Thread

import numpy as np
import pandas as pd
import pytrap
from cesnet_datazoo.config import DatasetConfig, Protocol
from cesnet_datazoo.constants import APP_COLUMN
from cesnet_datazoo.datasets import AVAILABLE_DATASETS
from cesnet_datazoo.utils.fileutils import yaml_load
from sklearn.metrics import accuracy_score, recall_score

from prediction_module import MAX_RECEIVE_SIZE, MAX_RECEIVE_TIME
from preprocessing.trie import create_trie, find_in_trie

TLS_PPI_MINLEN = 3
QUIC_PPI_MINLEN = 2


def init_trap():
    trap = pytrap.TrapCtx()
    trap.init(sys.argv, 1, 0)
    trap.setRequiredFmt(0, pytrap.FMT_UNIREC, "")
    print(f"Trap init complete")
    return trap

def data_receive_bulk(trap, cv):
    t_receive = threading.current_thread()
    print(f"Receiving bulk data with max buffer {MAX_RECEIVE_SIZE}")
    rec = pytrap.UnirecTemplate("")
    while getattr(t_receive, "do_run", True):
        with cv:
            global global_data_list
            try:
                global_data_list = trap.recvBulk(rec, time=MAX_RECEIVE_TIME, count=MAX_RECEIVE_SIZE)
            except Exception as e:
                print(f"recvBulk exception: {e}")
                break
            if not len(global_data_list):
                print("No data received. Exiting...")
                break
            cv.wait()

def data_process(cv):
    t_process = threading.current_thread()
    ppi_minlen = QUIC_PPI_MINLEN if is_quic else TLS_PPI_MINLEN
    print(f"Starting the evalution of {'QUIC' if is_quic else 'TLS'} traffic classification with {len(known_apps)} classes. Unknown traffic is ignored")
    i = 1
    while getattr(t_process, "do_run", True):
        with cv:
            if not len(global_data_list):
                continue
            else:
                data_list = global_data_list.copy()
                cv.notify()
        df = pd.DataFrame.from_records(data_list)
        if is_quic:
            df[APP_COLUMN] = df.QUIC_SNI.map(find_in_trie_fn) # TODO handle star domains
        else:
            df[APP_COLUMN] = df.TLS_SNI.map(find_in_trie_fn)
        df = df[df.PPI_PKT_LENGTHS.map(len) >= ppi_minlen]
        known_ratio = df.APP.isin(known_apps).sum() / len(df)
        df = df[df.APP.isin(known_apps)]
        labels = df[APP_COLUMN]
        model_preds = df["PREDICTED_LABEL_MODEL"]
        acc_model = accuracy_score(labels, model_preds)
        recall = recall_score(labels, model_preds, average="macro", zero_division=np.nan)
        print(f"Loop {i: >2} completed. Accuracy {acc_model * 100:.1f}%, recall {recall * 100:.1f}%, ratio of known apps traffic {known_ratio * 100:.1f}%")
        i += 1
    return

def main():
    mutex = Lock()
    cv = Condition(mutex)
    trap = init_trap()
    t_receive = Thread(target=data_receive_bulk, args=(trap, cv))
    t_process = Thread(target=data_process, args=(cv,))
    t_receive.start()
    t_process.start()

    t_receive.join()
    setattr(t_process, "do_run", False)
    t_process.join()
    trap.finalize()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config-path",required=True)
    parser.add_argument("--data-root", required=True)
    args, unknown = parser.parse_known_args()

    if not os.path.exists(args.config_path):
        raise RuntimeError(f"Config file {args.config_path} does not exist")
    if not os.path.exists(args.data_root):
        raise RuntimeError(f"Data root folder {args.data_root} does not exist")
    dataset_configuration = yaml_load(args.config_path)
    data_root = args.data_root

    dataset_configuration = yaml_load(args.config_path)
    dataset_class = AVAILABLE_DATASETS[dataset_configuration.pop("dataset_name")]
    datazoo_version = dataset_configuration.pop("datazoo_version")
    current_datazoo_version = version("cesnet-datazoo")
    if current_datazoo_version != datazoo_version:
        warnings.warn(f"The model's datazoo version ({datazoo_version}) does not match the current version ({current_datazoo_version})")
    dataset = dataset_class(data_root=args.data_root, size=dataset_configuration.pop("dataset_size"), skip_dataset_read_at_init=True)
    dataset_config = DatasetConfig(dataset=dataset, **dataset_configuration)
    dataset.set_dataset_config_and_initialize(dataset_config)
    encoder = dataset.encoder
    is_quic = dataset.metadata.protocol == Protocol.QUIC
    assert encoder is not None
    trie = create_trie(dataset.servicemap_path)
    find_in_trie_fn = partial(find_in_trie, trie=trie)
    known_apps = list(encoder.classes_)[:-1]

    global_data_list = []
    main()
