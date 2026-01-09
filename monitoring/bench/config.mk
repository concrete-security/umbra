SHELL := /bin/bash

SCRIPT := scripts/bench_tools.py

BENCHMARK_INPUT_DIR ?= benchmark_results/raw_results
BENCHMARK_OUTPUT_DIR ?= benchmark_results/processed_results

RUN_ID ?= None
SIDE ?= client
MACHINE ?= Phala-H200

SCHEME ?= https
VLLM_TARGET ?= vllm.concrete-security.com
URL ?= $(SCHEME)://$(VLLM_TARGET)
RUNTIME = $(if $(findstring concrete-security,$(URL)),CVM,VM)

MODEL ?= openai/gpt-oss-120b
ENDPOINT ?= /v1/chat/completions

#  Single-Run parameters
INPUT_SIZE ?= 128
OUTPUT_SIZE ?= 128
NUM_PROMPTS ?= 100
REQUEST_RATE ?= None
MAX_CONCURRENCY ?= None

# Available datasets:
# sharegpt, burstgpt, sonnet, random, random-mm, hf, custom, prefix_repetition, spec_bench
DATASET ?= random

# Dataset=burstgpt parameters
BURSTGPT_DATASET_PATH ?= data/BurstGPT_without_fails_2.csv

# Dataset=prefix_repetition parameters
PREFIX_LEN ?= 512
SUFFIX_LEN ?= 128
NUM_PREFIXES ?= 5
REPEAT_RATIO ?= 80
OUT_LEN_PREFIX ?= $(OUTPUT_SIZE)

#  Multiple-Runs parameters
RIN_LIST  ?= 128 512 4096
ROUT_LIST ?= 128 4096
RPS_LIST  ?= None 1 8
NP_LIST   ?= 100
MC_LIST   ?= None 10
