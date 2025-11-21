#!/usr/bin/env bash
set -Eeuo pipefail


# Export all .env variables
if [ -f .env ]; then
    set -o allexport
    source .env
    set +o allexport
fi

# Benchmark parameters
URL="${SCHEME}://${VLLM_TARGET}"

SIDE=${SIDE:-client}

VLLM_ENDPOINT=${VLLM_ENDPOINT:-/v1/chat/completions}
MAXSEQ=${MAXSEQ:-8}
FREQUENCY=${FREQUENCY:-8}
NB_REQUESTS=${NB_REQUESTS:-2}

INPUT_SIZE=${INPUT_SIZE:-20}
OUTPUT_SIZE=${OUTPUT_SIZE:-512}

DATASET=${DATASET:-random}               # or HF
DPATH=${DPATH:-AI-MO/NuminaMath-CoT}

BENCHMARK_INPUT_DIR=${BENCHMARK_INPUT_DIR:-toto/raw_results/}

HEADER_REQUESTS="timestamp,running,waiting,kv_cache"
HEADER_GPU=${HEADER_GPU:-"timestamp,index,name,utilization.gpu,utilization.memory,memory.used,memory.total"}

NVIDIA_SMI_QUERY=${NVIDIA_SMI_QUERY:-index,name,utilization.gpu,utilization.memory,memory.used,memory.total}

SAVE=${SAVE:-false}
VERBOSE=${VERBOSE:-false}


build_filename() {
    # Helper to build standardized filenames containing hyperparameters
    local id="$1"
    local prefix="$2"
    local extension="$3"
    printf "%s/bench_%s_%s_machine%s_side%s_input%s_out%s_parallel%s_rps%s_np%s_dataset%s.%s" \
        "${BENCHMARK_INPUT_DIR}" "${id}" "${prefix}" "${MACHINE}" "${SIDE}" \
        "${INPUT_SIZE}" "${OUTPUT_SIZE}" "${MAXSEQ}" "${FREQUENCY}" "${NB_REQUESTS}" "${DATASET}" "${extension}"
}


generate_id() {
    # Generate a random run ID
    openssl rand -hex 4
}


ensure_dir() {
    # Ensure the result directory exists
    mkdir -p "${BENCHMARK_INPUT_DIR}"
}


single_vllm_bench() {
    # Run a single vLLM benchmark
    # Hyperparameter examples:
    # --random-input-len: set via INPUT_SIZE
    # --random-output-len: set via OUTPUT_SIZE
    # --request-rate: set via FREQUENCY
    # --num-prompts: set via NB_REQUESTS

    ensure_dir

    local id_gen=$(generate_id)
    local file_name=$(build_filename "${id_gen}" "vllm" "json")
    local file_base=$(basename "${file_name}")

    echo "🌐 Selected URL=${URL}"
    echo "🚀 Running vLLM bench with MACHINE=${MACHINE} URL=${URL} SIDE=${SIDE} DATASET=${DATASET}"
    echo "Input=${INPUT_SIZE} Output=${OUTPUT_SIZE} PARALLEL=${MAXSEQ} FREQUENCE=${FREQUENCY} TOTAL_QUERY=${NB_REQUESTS}"

    uv run --group bench --active -- vllm bench serve \
        --backend openai-chat \
        --base-url "${URL}" \
        --endpoint "${VLLM_ENDPOINT}" \
        --model openai/gpt-oss-120b \
        --dataset-name "${DATASET}" \
        --random-input-len "${INPUT_SIZE}" \
        --random-output-len "${OUTPUT_SIZE}" \
        --request-rate "${FREQUENCY}" \
        --num-prompts "${NB_REQUESTS}" \
        --save-result \
        --result-dir "${BENCHMARK_INPUT_DIR}" \
        --result-filename "${file_base}"

    echo "✅ Results saved to ${BENCHMARK_INPUT_DIR}/${file_base}"
}


gpu_metrics() {
    # VERBOSE=true SAVE=true ./bench_tools.sh gpu_metrics
    ensure_dir

    local id_gen=$(generate_id)
    local file_name=$(build_filename "${id_gen}" "gpu" "csv")
    if [[ "${SAVE}" == "true" ]]; then
        echo "🚀 Saving file: ${file_name}"
        echo "${HEADER_GPU}" > "${file_name}"
    fi

    if [[ "${VERBOSE}" == "true" ]]; then
        echo "🚀 GPU metrics..."
        echo "${HEADER_GPU}"
    fi

    while true; do
        local ts=$(date +%Y-%m-%dT%H:%M:%S)

        nvidia-smi --query-gpu="${NVIDIA_SMI_QUERY}" --format=csv,noheader,nounits | \
        while IFS=, read -r index name ugpu umem mused mtotal; do
            local line
            line=$(printf "%s,%s,%s,%s,%s,%s,%s\n" \
                    "${ts}" "${index}" "${name}" "${ugpu}" "${umem}" "${mused}" "${mtotal}")

            if [[ "${SAVE}" == "true" ]]; then
                echo "${line}" >> "${file_name}"
            fi

            if [[ "${VERBOSE}" == "true" ]]; then
                echo "${line}"
            fi
        done

        sleep 1
    done
}


requests_metrics() {
    # VERBOSE=true SAVE=true ./bench_tools.sh requests_metrics
    ensure_dir

    local id_gen=$(generate_id)
    local file_name=$(build_filename "${id_gen}" "request" "csv")

    if [[ "${SAVE}" == "true" ]]; then
        echo "🚀 Saving file: ${file_name}"
        echo "${HEADER_REQUESTS}" > "${file_name}"
    fi

    if [[ "${VERBOSE}" == "true" ]]; then
        echo "🚀 Starting vLLM request metrics..."
        echo "${HEADER_REQUESTS}"
    fi

    while true; do
        local ts
        ts=$(date +%Y-%m-%dT%H:%M:%S)

        local running
        local waiting
        local kvcache

        running=$(curl -s "${URL}" | grep "^vllm:num_requests_running" | awk '{print $2}')
        waiting=$(curl -s "${URL}" | grep "^vllm:num_requests_waiting" | awk '{print $2}')
        kvcache=$(curl -s "${URL}" | grep -E "cache.*usage|kv.*cache.*usage" | awk '{print $2}' | head -n 1)

        [[ -z "${running}" ]] && running="0"
        [[ -z "${waiting}" ]] && waiting="0"
        [[ -z "${kvcache}" ]] && kvcache="NA"

        if [[ "${VERBOSE}" == "true" ]]; then
            printf "%s,%s,%s,%s\n" "${ts}" "${running}" "${waiting}" "${kvcache}"
        fi

        if [[ "${SAVE}" == "true" ]]; then
            printf "%s,%s,%s,%s\n" "${ts}" "${running}" "${waiting}" "${kvcache}" >> "${file_name}"
        fi

        sleep 1
    done
}


bench_loop() {
    # Run multiple benchmarks over a grid of hyperparameters
    # Example:
    # ./bench_tools.sh bench_loop "110" "110" "1" "1"

    local rin_list="${1:-110000}"
    local rout_list="${2:-110000}"
    local rps_list="${3:-1}"
    local np_list="${4:-1}"

    local use_metrics="${5:-false}"
    local verbose="${6:-false}"
    local save="${7:-false}"

    echo "🚀🚀🚀🚀 Starting benchmark loop for ${URL} 🚀🚀🚀🚀🚀"

    for input_size in $rin_list; do
      for output_size in $rout_list; do
        for frequency in $rps_list; do
          for nb_requests in $np_list; do

            ID=$(openssl rand -hex 4)

            echo "Starting benchmark run ID=$ID - INPUT_SIZE=$input_size OUTPUT_SIZE=$output_size FREQUENCY=$frequency NB_REQUESTS=$nb_requests"

            local GPU_PID=""
            local REQ_PID=""

            if [[ "$use_metrics" == "true" ]]; then
                SAVE="$save" VERBOSE="$verbose" \
                ID="$ID" MACHINE="$MACHINE" SIDE="$SIDE" \
                INPUT_SIZE="$input_size" OUTPUT_SIZE="$output_size" FREQUENCY="$frequency" NB_REQUESTS="$nb_requests" \
                DATASET="$DATASET" MAXSEQ="$MAXSEQ" \
                gpu_metrics &
                GPU_PID=$!

                SAVE="$save" VERBOSE="$verbose" \
                ID="$ID" MACHINE="$MACHINE" SIDE="$SIDE" \
                INPUT_SIZE="$input_size" OUTPUT_SIZE="$output_size" FREQUENCY="$frequency" NB_REQUESTS="$nb_requests" \
                DATASET="$DATASET" MAXSEQ="$MAXSEQ" \
                requests_metrics &
                REQ_PID=$!
            fi

            # Bench principal
            ID="$ID" MACHINE="$MACHINE" SIDE="$SIDE" \
            INPUT_SIZE="$input_size" OUTPUT_SIZE="$output_size" FREQUENCY="$frequency" NB_REQUESTS="$nb_requests" \
            DATASET="$DATASET" MAXSEQ="$MAXSEQ" \
            single_vllm_bench

            # Arrêt propre des métriques
            if [[ -n "$GPU_PID" ]]; then
                kill "$GPU_PID" 2>/dev/null || true
                wait "$GPU_PID" 2>/dev/null || true
            fi

            if [[ -n "$REQ_PID" ]]; then
                kill "$REQ_PID" 2>/dev/null || true
                wait "$REQ_PID" 2>/dev/null || true
            fi

            echo "✅ Run $ID completed successfully!"
            sleep 10

          done
        done
      done
    done
}

# CLI entrypoint
usage() {
    cat <<EOF
Usage: $(basename "$0") <function> [arguments]

Commands:
  gpu_metrics       Run GPU metrics
  requests_metrics  Run request metrics (running/waiting queries)
  vllm_bench        Run vLLM benchmark
  bench_loop        Run a loop of benchmarks with different parameters

Examples:
  $(basename "$0") vllm_bench
  $(basename "$0") gpu_metrics
  $(basename "$0") bench_loop "110000 220000" "110000" "100" "100" true true true false
EOF
}

main() {
    local cmd="${1:-help}"
    shift || true

    case "${cmd}" in
        gpu_metrics|requests_metrics|single_vllm_bench|bench_loop)
            "${cmd}" "$@"
            ;;
        help|-h|--help)
            usage
            ;;
        *)
            echo "Unknown command: ${cmd}" >&2
            usage
            exit 1
            ;;
    esac
}

main "$@"
