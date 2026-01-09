import os
import re
import time
import uuid
import json
import argparse
import subprocess
import pandas as pd
from tqdm import tqdm
from pathlib import Path


# Configuration
SHORT_NAMES = {
    "random-input-len": "inLen",
    "random-output-len": "outLen",
    "prefix-repetition-num-prefixes": "preNum",
    "prefix-repetition-prefix-len": "preLen",
    "prefix-repetition-suffix-len": "sufLen",
    "prefix-repetition-output-len": "preOutLen",
    "dataset-name": "ds",
    "num-prompts": "np",
    # max-concurrency is already mentioned in the generated vllm json report
}

def sanitize(text):
    assert text, f"`{text}` is empty"
    text = re.sub(r'[^a-zA-Z0-9-]', '-', str(text))
    text = re.sub(r'-+', '-', text).strip('-')
    assert text, f"Failed to sanitized: `{text}`"
    return text

def single_run(args, extra_params):
    run_id = uuid.uuid4().hex[:5] if args.run_id is None or str(args.run_id).lower() == "none" else args.run_id
    extra_params.sort()

    base_url_fn = sanitize(args.url.split('//')[-1].split(':')[0])
    endpoint_label = "chat" if "chat" in args.endpoint else "responses"

    raw_filename_params = [
        f"id={run_id}",
        f"machine={args.machine}",
        f"runtime={args.runtime}",
        f"side={args.side}",
        f"url={base_url_fn}",
        f"endpoint={endpoint_label}",
        f"max-seq=8",
    ] + extra_params

    sanitized_parts = []
    for param in raw_filename_params:
        if '=' not in param: continue
        k, v = param.split('=', 1)
        k = SHORT_NAMES.get(k, sanitize(k))
        sanitized_parts.append(f"{k}={sanitize(v)}")

    filename = f"bench_{'_'.join(sanitized_parts)}.json"

    # `bench serve`: Estimate performance under actual operating conditions
    vllm_cmd = [
        "uv", "run", "--group", "bench", "--active", "--",
        "vllm", "bench", "serve",
        "--base-url", args.url,
        "--model", args.model,
        "--save-result",
        # "--save-detailed",
        "--result-dir", args.input_dir,
        "--result-filename", filename
    ]

    for p in extra_params:
        if '=' not in p: continue
        key, val = p.split("=", 1)
        if key == 'max-concurrency' and str(val).lower() == 'none': continue
        if key == 'request-rate' and str(val).lower() == 'none': continue
        vllm_cmd.extend([f"--{key}", val])

    os.makedirs(args.input_dir, exist_ok=True)

    subprocess.run(vllm_cmd)
    print(f"🚀 Filename: `{filename}`")

def multiple_runs(args, extra_params):
    in_list = args.in_list.split()
    out_list = args.out_list.split()
    rps_list = args.rps_list.split()
    np_list = args.np_list.split()
    mc_list = args.mc_list.split()

    # Optional lists
    if not rps_list: rps_list = ["None"]
    if not mc_list: mc_list = ["None"]

    print(
        "🌀 Starting Benchmark Loop: "
        f"{len(in_list)*len(out_list)*len(rps_list)*len(np_list)*len(mc_list)}` runs planned."
    )

    for in_sz in in_list:
        for out_sz in out_list:
            for rps in rps_list:
                for np in np_list:
                    for mc in mc_list:
                        current_extras = extra_params.copy()
                        current_extras.append(f"random-input-len={in_sz}")
                        current_extras.append(f"random-output-len={out_sz}")
                        current_extras.append(f"num-prompts={np}")

                        # Optional
                        if rps.lower() != "none":
                            current_extras.append(f"request-rate={rps}")
                        if mc.lower() != "none":
                            current_extras.append(f"max-concurrency={mc}")
                        single_run(args, current_extras)

                        print("-" * 40)
                        time.sleep(2)

def extract_bench_params(filename: str):
    stem = Path(filename).stem
    assert stem.startswith("bench_")
    stem = stem[6:]
    params = {}
    parts = stem.split("_")
    for part in parts:
        key, val = part.split("=", 1)
        params[key] = val
    return params

def combine_results(input_dir, output_dir):
    input_path = Path(input_dir)
    json_files = list(input_path.glob("*.json"))

    assert len(json_files) >= 1, f"❌ No JSON files found in `{input_dir}`"

    print(f"Combining `{len(json_files)}` files...")

    rows = []
    for f in tqdm(json_files):
        try:
            with open(f, 'r') as jfile:
                json_data = json.load(jfile)

            df_vllm = pd.json_normalize(json_data, sep=".")
            df_params = pd.DataFrame([extract_bench_params(f.name)])
            rows.append(pd.concat([df_params, df_vllm], axis=1))
        except Exception as e:
            print(f"⚠️ Error processing `{f.name}`: `{e}`")

    df_final = pd.concat(rows, axis=0, ignore_index=True)
    os.makedirs(output_dir, exist_ok=True)
    out_file = Path(output_dir) / "combined_bench_results.csv"
    df_final.to_csv(out_file, index=False)
    print(f"✅ CSV saved to: `{out_file}`")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="vLLM Bench Engine")
    subparsers = parser.add_subparsers(dest="action", required=True)

    # BLOC 1 : SINGLE-RUN
    parser_single = subparsers.add_parser("single-run", help="Run one benchmark")
    parser_single.add_argument("--url", required=True)
    parser_single.add_argument("--run_id", default=None)
    parser_single.add_argument("--model", required=True)
    parser_single.add_argument("--machine", default=None)
    parser_single.add_argument("--runtime", default=None)
    parser_single.add_argument("--side", default="client")
    parser_single.add_argument("--endpoint", default="/v1/chat/completions")
    parser_single.add_argument("--input-dir", default="toto/raw_results")

    # BLOC 2 : MULTIPLE-RUNS
    parser_loop = subparsers.add_parser("multiple-runs", help="Run multiple benchmarks")
    parser_loop.add_argument("--url", required=True)
    parser_loop.add_argument("--run_id", default=None)
    parser_loop.add_argument("--model", required=True)
    parser_loop.add_argument("--in_list", required=True)
    parser_loop.add_argument("--out_list", required=True)
    parser_loop.add_argument("--rps_list", default="None")
    parser_loop.add_argument("--np_list", default="10")
    parser_loop.add_argument("--mc_list", default="None")

    parser_loop.add_argument("--machine", default="none")
    parser_loop.add_argument("--runtime", default="none")
    parser_loop.add_argument("--side", default="client")
    parser_loop.add_argument("--endpoint", default="/v1/chat/completions")
    parser_loop.add_argument("--input-dir", default="toto/raw_results")

    # BLOC 3 : COMBINE FILES
    parser_combine = subparsers.add_parser("combine", help="Merge results into CSV")
    parser_combine.add_argument("--input-dir", default="toto/raw_results")
    parser_combine.add_argument("--output_dir", default="toto/processed_results")

    # Parsing
    args, extra_params = parser.parse_known_args()

    if args.action == 'multiple-runs':
        multiple_runs(args, extra_params)

    elif args.action == 'single-run':
        single_run(args, extra_params)

    elif args.action == 'combine':
        combine_results(args.input_dir, args.output_dir)
    else:
        raise ValueError(f"Unknown action: `{args.action}`")
