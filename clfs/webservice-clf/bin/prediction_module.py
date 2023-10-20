#!/usr/bin/env python3.11

# (C) 2023 CESNET z.s.p.o. Prague, Czech Republic
# (C) 2023 FIT CTU in Prague, Czech Republic
# (C) 2023 FIT VUT in Brno, Czech Republic

import argparse
import itertools
import os
import sys
import threading
import time
import warnings
from datetime import timedelta
from functools import partial
from importlib.metadata import version
from multiprocessing.pool import ThreadPool
from threading import Condition, Lock, Thread
from typing import Optional

import lightgbm as lgb
import numpy as np
import pandas as pd
import pytrap
import torch
from cesnet_datazoo.config import DatasetConfig, Protocol
from cesnet_datazoo.constants import PPI_COLUMN, PPI_MAX_LEN, UNKNOWN_STR_LABEL
from cesnet_datazoo.datasets import AVAILABLE_DATASETS
from cesnet_datazoo.utils.fileutils import yaml_load

ORIGINAL_COLUMNS_TO_DROP = ["PPI_PKT_TIMES", "PPI_PKT_DIRECTIONS", "PPI_PKT_LENGTHS", "PPI_PKT_FLAGS", "S_PHISTS_SIZES", "D_PHISTS_SIZES", "S_PHISTS_IPT", "D_PHISTS_IPT",
                            "TIME_FIRST", "TIME_LAST", "TCP_FLAGS", "TCP_FLAGS_REV", "FLOW_END_REASON"]
MAX_RECEIVE_SIZE = 10000
MAX_RECEIVE_TIME = 1000
MESSAGE_BUFFER_SIZE = 2000
TLS_COLUMNS = ["TIME_FIRST", "TIME_LAST",
               "BYTES", "BYTES_REV",
               "PACKETS", "PACKETS_REV",
               "TCP_FLAGS", "TCP_FLAGS_REV",
               "PPI_PKT_TIMES", "PPI_PKT_DIRECTIONS", "PPI_PKT_LENGTHS", "PPI_PKT_FLAGS",
               "S_PHISTS_SIZES", "D_PHISTS_SIZES", "S_PHISTS_IPT", "D_PHISTS_IPT",
               "FLOW_END_REASON"]
QUIC_COLUMNS = ["TIME_FIRST", "TIME_LAST",
                "BYTES", "BYTES_REV",
                "PACKETS", "PACKETS_REV",
                "PPI_PKT_TIMES", "PPI_PKT_DIRECTIONS", "PPI_PKT_LENGTHS", "PPI_PKT_FLAGS",
                "S_PHISTS_SIZES", "D_PHISTS_SIZES", "S_PHISTS_IPT", "D_PHISTS_IPT",
                "FLOW_END_REASON"]
QUIC_DATA_DTYPE = np.dtype([("DURATION", "<f4"), ("BYTES", "<u8"), ("BYTES_REV", "<u8"), ("PACKETS", "<u4"), ("PACKETS_REV", "<u4"), ("PPI", "<f4", (3, 30)), ("PPI_LEN", "<u2"), ("PPI_DURATION", "<f4"), ("PPI_ROUNDTRIPS", "<u2"), ("PHIST_SRC_SIZES", "<u4", (8,)), ("PHIST_DST_SIZES", "<u4", (8,)), ("PHIST_SRC_IPT", "<u4", (8,)), ("PHIST_DST_IPT", "<u4", (8,)), ("FLOW_ENDREASON_IDLE", "?"), ("FLOW_ENDREASON_ACTIVE", "?"), ("FLOW_ENDREASON_OTHER", "?")])
TLS_DATA_DTYPE = np.dtype([("DURATION", "<f4"), ("BYTES", "<u8"), ("BYTES_REV", "<u8"), ("PACKETS", "<u4"), ("PACKETS_REV", "<u4"), ("PPI", "<i4", (4, 30)), ("PPI_LEN", "<u2"), ("PPI_DURATION", "<f4"), ("PPI_ROUNDTRIPS", "<u2"), ("PHIST_SRC_SIZES", "<u4", (8,)), ("PHIST_DST_SIZES", "<u4", (8,)), ("PHIST_SRC_IPT", "<u4", (8,)), ("PHIST_DST_IPT", "<u4", (8,)), ("FLAG_CWR", "?"), ("FLAG_CWR_REV", "?"), ("FLAG_ECE", "?"), ("FLAG_ECE_REV", "?"), ("FLAG_URG", "?"), ("FLAG_URG_REV", "?"), ("FLAG_ACK", "?"), ("FLAG_ACK_REV", "?"), ("FLAG_PSH", "?"), ("FLAG_PSH_REV", "?"), ("FLAG_RST", "?"), ("FLAG_RST_REV", "?"), ("FLAG_SYN", "?"), ("FLAG_SYN_REV", "?"), ("FLAG_FIN", "?"), ("FLAG_FIN_REV", "?"), ("FLOW_ENDREASON_IDLE", "?"), ("FLOW_ENDREASON_ACTIVE", "?"), ("FLOW_ENDREASON_END", "?"), ("FLOW_ENDREASON_OTHER", "?")])
DATA_PROCESSING_THREADS = 4
LIGHTGBM_THREADS = 4
THREAD_POOL_CHUNKSIZE = 500

def process_ppi_row(row: dict, use_push_flags: bool = True) -> None:
    sizes = row["PPI_PKT_LENGTHS"]
    directions = row["PPI_PKT_DIRECTIONS"]
    times = [x.toDatetime() for x in row["PPI_PKT_TIMES"]]
    time_differences = [int((e - s) / timedelta(milliseconds=1)) for s, e in zip(times, times[1:])]
    time_differences.insert(0, 0)
    ppi_roundtrips = len(list(itertools.groupby(itertools.dropwhile(lambda x: x < 0, directions), key=lambda i: i > 0))) // 2
    ppi_len = len(sizes)
    ppi_duration = (times[-1] - times[0]).total_seconds()
    if ppi_len != PPI_MAX_LEN:
        time_differences = time_differences + [0] * (PPI_MAX_LEN - ppi_len)
        directions = directions + [0] * (PPI_MAX_LEN - ppi_len)
        sizes = sizes + [0] * (PPI_MAX_LEN - ppi_len)
    if use_push_flags:
        push_flags = list(map(lambda x: int(x) & 8 != 0 , row["PPI_PKT_FLAGS"]))
        push_flags = push_flags + [0] * (PPI_MAX_LEN - ppi_len)
        ppi = (time_differences, directions, sizes, push_flags)
    else:
        ppi = (time_differences, directions, sizes)
    row[PPI_COLUMN] = ppi
    row["PPI_LEN"] = ppi_len
    row["PPI_DURATION"] = ppi_duration
    row["PPI_ROUNDTRIPS"] = ppi_roundtrips
    return

def add_tcp_flags_row(row: dict) -> None:
    row["FLAG_CWR"], row["FLAG_CWR_REV"] = (row["TCP_FLAGS"] & 128) != 0, (row["TCP_FLAGS_REV"] & 128) != 0
    row["FLAG_ECE"], row["FLAG_ECE_REV"] = (row["TCP_FLAGS"] & 64) != 0, (row["TCP_FLAGS_REV"] & 64) != 0
    row["FLAG_URG"], row["FLAG_URG_REV"] = (row["TCP_FLAGS"] & 32) != 0, (row["TCP_FLAGS_REV"] & 32) != 0
    row["FLAG_ACK"], row["FLAG_ACK_REV"] = (row["TCP_FLAGS"] & 16) != 0, (row["TCP_FLAGS_REV"] & 16) != 0
    row["FLAG_PSH"], row["FLAG_PSH_REV"] = (row["TCP_FLAGS"] & 8) != 0, (row["TCP_FLAGS_REV"] & 8) != 0
    row["FLAG_RST"], row["FLAG_RST_REV"] = (row["TCP_FLAGS"] & 4) != 0, (row["TCP_FLAGS_REV"] & 4) != 0
    row["FLAG_SYN"], row["FLAG_SYN_REV"] = (row["TCP_FLAGS"] & 2) != 0, (row["TCP_FLAGS_REV"] & 2) != 0
    row["FLAG_FIN"], row["FLAG_FIN_REV"] = (row["TCP_FLAGS"] & 1) != 0, (row["TCP_FLAGS_REV"] & 1) != 0
    return

def add_flowendreason_row(row: dict) -> None:
    row["FLOW_ENDREASON_IDLE"] = row["FLOW_END_REASON"] == 1
    row["FLOW_ENDREASON_ACTIVE"] = row["FLOW_END_REASON"] == 2
    row["FLOW_ENDREASON_END"] = row["FLOW_END_REASON"] == 3
    row["FLOW_ENDREASON_OTHER"] = (row["FLOW_END_REASON"] == 4) | (row["FLOW_END_REASON"] == 5)
    return

def process_row(row, is_quic, data_dtype):
    row["PHIST_SRC_SIZES"] = row["S_PHISTS_SIZES"]
    row["PHIST_DST_SIZES"] = row["D_PHISTS_SIZES"]
    row["PHIST_SRC_IPT"] = row["S_PHISTS_IPT"]
    row["PHIST_DST_IPT"] = row["D_PHISTS_IPT"]
    row["TIME_FIRST"] = row["TIME_FIRST"].toDatetime()
    row["TIME_LAST"] = row["TIME_LAST"].toDatetime()
    row["DURATION"] = (row["TIME_LAST"] - row["TIME_FIRST"]) / pd.Timedelta(seconds=1)
    add_flowendreason_row(row)
    if not is_quic:
        add_tcp_flags_row(row)
    process_ppi_row(row, use_push_flags=not is_quic)
    return tuple((row[f] for f in data_dtype.names))

def process_dataframe_nemea(data_list: list[dict], is_quic: bool, pool: Optional[ThreadPool]) -> np.ndarray:
    data_dtype = QUIC_DATA_DTYPE if is_quic else TLS_DATA_DTYPE
    if pool:
        data = pool.map(partial(process_row, is_quic=is_quic, data_dtype=data_dtype), data_list, chunksize=THREAD_POOL_CHUNKSIZE)
    else:
        data = [process_row(row, is_quic=is_quic, data_dtype=data_dtype) for row in data_list]
    data = np.array(data, dtype=data_dtype)
    return data

def init_trap():
    trap = pytrap.TrapCtx()
    trap.init(sys.argv, 1, 1)
    trap.setRequiredFmt(0, pytrap.FMT_UNIREC, "")
    print(f"Trap init complete")
    return trap

def init_send_buffer(trap):
    _, inputspec = trap.getDataFmt(0)
    outputspec = inputspec + ",string PREDICTED_LABEL_MODEL"
    rec = pytrap.UnirecTemplate(outputspec)
    message_buffer = rec.createMessage(MESSAGE_BUFFER_SIZE)
    trap.setDataFmt(0, pytrap.FMT_UNIREC, outputspec)
    return rec, message_buffer, inputspec

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

def data_send(data_list: list[dict], model_preds: np.ndarray, trap, rec, message_buffer, input_fields: list[str]):
    for i, row in enumerate(data_list):
        for field in input_fields:
            rec.set(message_buffer, field, row[field])
        rec.set(message_buffer, "PREDICTED_LABEL_MODEL",  model_preds[i])
        try:
            trap.send(message_buffer)
        except pytrap.TimeoutError: # TODO handle NO_WAIT mode
            continue
    return

def data_process(trap, cv):
    assert collate_fn is not None and encoder is not None
    t_process = threading.current_thread()
    rec, message_buffer, inputspec = init_send_buffer(trap)
    input_fields = list(map(lambda x: x.split()[1], inputspec.split(",")))
    i = 1
    if DATA_PROCESSING_THREADS > 0:
        pool = ThreadPool(processes=DATA_PROCESSING_THREADS)
    else:
        pool = None
    print(f"Computing web service predictions in {'QUIC' if is_quic else 'TLS'} traffic")
    while getattr(t_process, "do_run", True):
        with cv:
            if not len(global_data_list):
                continue
            else:
                loop_start = time.time()
                data_list = global_data_list.copy()
                cv.notify()
        start_time = time.time()
        data = process_dataframe_nemea(data_list, is_quic=is_quic, pool=pool)
        print(f" - Processing data took {time.time() - start_time:.1f} seconds")
        # Compute model predictions
        start_time = time.time()
        *batch_data, _ = collate_fn((data[PPI_COLUMN].astype("float32"), data[dataset_config.flowstats_features], np.repeat(UNKNOWN_STR_LABEL, len(data))))
        if isinstance(model, torch.nn.Module):
            batch_data[0], batch_data[1] = batch_data[0].to(device), batch_data[1].to(device)
            with torch.no_grad():
                out = model(batch_data)
            model_preds = out.argmax(dim=1).cpu()
        elif isinstance(model, lgb.Booster):
            batch_ppi, batch_flowstats = batch_data
            batch_ppi = batch_ppi.reshape(batch_ppi.shape[0], -1)
            lgb_input_data = np.column_stack((batch_ppi, batch_flowstats))
            model_preds = model.predict(lgb_input_data, num_iteration=model.best_iteration, num_threads=LIGHTGBM_THREADS).argmax(axis=1) # type: ignore
        else:
            raise RuntimeError(f"Unsupported model")
        model_preds = encoder.inverse_transform(model_preds)
        print(f" - Computing model predictions took {time.time() - start_time:.1f} seconds")

        # Create messages and send data to output interface
        start_time = time.time()
        data_send(data_list, model_preds, trap, rec, message_buffer, input_fields)
        print(f" - Sending data took {time.time() - start_time:.1f} seconds")
        print(f"Loop {i: >2} completed. Total time {time.time() - loop_start:.1f} seconds")
        i += 1
    if pool:
        pool.close()

def main():
    mutex = Lock()
    cv = Condition(mutex)
    trap = init_trap()
    t_receive = Thread(target=data_receive_bulk, args=(trap, cv))
    t_process = Thread(target=data_process, args=(trap, cv))
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
    parser.add_argument("--model-path", required=True)
    args, unknown = parser.parse_known_args()
    if not os.path.exists(args.config_path):
        raise RuntimeError(f"Config file {args.config_path} does not exist")
    if not os.path.exists(args.data_root):
        raise RuntimeError(f"Data root folder {args.data_root} does not exist")
    if not os.path.exists(args.model_path):
        raise RuntimeError(f"Model path {args.model_path} does not exist")

    dataset_configuration = yaml_load(args.config_path)
    dataset_class = AVAILABLE_DATASETS[dataset_configuration.pop("dataset_name")]
    datazoo_version = dataset_configuration.pop("datazoo_version")
    current_datazoo_version = version("cesnet-datazoo")
    if current_datazoo_version != datazoo_version:
        warnings.warn(f"The model's datazoo version ({datazoo_version}) does not match the current version ({current_datazoo_version})")
    dataset = dataset_class(data_root=args.data_root, size=dataset_configuration.pop("dataset_size"), skip_dataset_read_at_init=True)
    dataset_config = DatasetConfig(dataset=dataset, **dataset_configuration)
    dataset.set_dataset_config_and_initialize(dataset_config)
    collate_fn = dataset.collate_fn
    encoder = dataset.encoder
    is_quic = dataset.metadata.protocol == Protocol.QUIC

    if args.model_path.endswith(".pickle"):
        device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
        model = torch.load(args.model_path, map_location=device)
        model = model.to(device)
        model.eval()
    elif "lightgbm" in os.path.basename(args.model_path) and args.model_path.endswith(".txt"):
        model = lgb.Booster(model_file=args.model_path)
    else:
        raise RuntimeError(f"Unsupported model file {args.model_path}")

    global_data_list = []
    main()
