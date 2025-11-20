import os
import re
import json
import argparse
import pandas as pd

from pathlib import Path

from tqdm import tqdm


PATTERN = re.compile(r"bench_([0-9a-fA-F]+)_(memory|request|vllm)_")
DIR_PATH = Path('../../monitoring/vllm_bench_serve_results')


def load_csv(file_path):
    return pd.read_csv(file_path)


def load_json(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)


def flatten_describe(df):
    desc = df.describe().stack().reset_index()
    desc["feature"] = desc["level_1"] + "_" + desc["level_0"]
    desc["row"] = 0
    out = desc.pivot(index="row", columns="feature", values=0)
    return out.reset_index(drop=True)


def organize_files_by_uid(input_dir_path):
    files_by_uid = {}
    for fname in tqdm(os.listdir(input_dir_path)):
        match = PATTERN.search(fname)

        if not match:
            continue

        uid, ftype = match.groups()
        files_by_uid.setdefault(uid, {})[ftype] = input_dir_path / fname

    print(f"`{len(files_by_uid)}` unique UIDs found.")
    return files_by_uid


def concat_all_results(files_by_uid, other_metrics=False):
    rows = []

    for i, (uid, files) in tqdm(enumerate(files_by_uid.items())):
        if other_metrics and len(files) < 3:
            print(f"Missing files for UID {uid} - Skipping")
            continue

        df_vllm = pd.json_normalize(load_json(files['vllm']), sep=".")

        other_infos = extract_bench_params(files['vllm'])
        df_params = pd.DataFrame([other_infos])

        if other_metrics:
            data_request = load_csv(files['request'])
            pd_request = flatten_describe(data_request)

            data_resources = load_csv(files['memory'])
            pd_resources = flatten_describe(data_resources)

            df_row = pd.concat([df_params, df_vllm, pd_request, pd_resources], axis=1)
        else:
            df_row = pd.concat([df_params, df_vllm], axis=1)

        df_row["uid"] = uid

        rows.append(df_row)

    print(f"`{len(rows)}` rows processed.")

    return pd.concat(rows, axis=0, ignore_index=True)


def extract_bench_params(filename: str):
    name = Path(filename).name
    params = {}
    m = re.search(r"machine([A-Za-z0-9]+)", name)
    params["machine"] = m.group(1) if m else None

    m = re.search(r"side([A-Za-z0-9]+)", name)
    params["side"] = m.group(1) if m else None

    m = re.search(r"input([0-9]+)", name)
    params["input"] = int(m.group(1)) if m else None

    m = re.search(r"out([0-9]+)", name)
    params["out"] = int(m.group(1)) if m else None

    m = re.search(r"parallel_([0-9]+)", name)
    params["parallel"] = int(m.group(1)) if m else None

    m = re.search(r"rps([0-9]+)", name)
    params["rps"] = int(m.group(1)) if m else None

    m = re.search(r"np([0-9]+)", name)
    params["np"] = int(m.group(1)) if m else None

    m = re.search(r"dataset([A-Za-z0-9]+)", name)
    params["dataset"] = m.group(1) if m else None

    return params


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Combine vLLM benchmark results into a single CSV file."
    )
    parser.add_argument(
        "--input_dir",
        help="Directory containing bench_*.json / bench_*_(request|memory).csv files",
    )

    parser.add_argument(
        "--output_dir",
        help="Directory containing the combined and processed CSV file.",
    )
    parser.add_argument(
        "--other-metrics",
        default=False,
        help="Whether to aggregate request + memory metrics to the final CSV file.",
    )

    args = parser.parse_args()

    input_dir_path = Path(args.input_dir)
    output_dir_path = Path(args.output_dir)
    other_metrics = args.other_metrics

    nb_files = len(list(input_dir_path.glob('*.json')))
    if nb_files == 0:
        raise ValueError(f"No files `{nb_files=}` found in `{input_dir_path}`")
    print(f"Found `{nb_files=}` files in `{input_dir_path}`")

    files_by_uid = organize_files_by_uid(input_dir_path)

    df_all = concat_all_results(files_by_uid, other_metrics)

    os.makedirs(output_dir_path, exist_ok=True)
    df_all.to_csv(output_dir_path / "combined_bench_results.csv", index=False)
