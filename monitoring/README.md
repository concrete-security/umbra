# Monitoring Stack

This directory provides a fully containerized monitoring stack built on _Prometheus_ and _Grafana_, designed to track and assess **vLLM** model performance in real-time.

- **vLLM** exposes a `/metrics` endpoint with detailed runtime metrics about the model.
- **Prometheus** continuously scrapes this endpoint and stores the data as structured time series.
- **Grafana** then displays these metrics using dashboards.
    Two dashboards are available:
    - User overview: TTFT, end-to-end latency, queue waiting time, number of running requests, etc.
    - Machine overview: GPU usage, memory and CPU workload, running/waiting requests, and more.


## Configuration Strategy

This stack uses a 2-step process to manage sensitive files:

- Secrets (Auth Tokens, IPs) are stored in `.env`
- Config files are generated from .template files. A whitelist ensures only secrets are replaced, protecting internal variables like $job or $datasource.
- Configuration files are generated on build and wiped on stop

Ensure your `.env` is populated before starting (see .env_example):

```env
# Grafana credentials (used for local Grafana instance)
ADMIN_USER=
ADMIN_PASSWORD=

# vLLM target details
VLLM_TARGET=
SCHEMA=https  # Use 'https' for remote endpoints, 'http' for local
VLLM_METRICS_AUTH_TOKEN=bearer_token  # Required for remote vllm /metrics access
```


## Starting the Monitoring Stack

| Command                | Description |
| ---------------------- | ----------- |
| `make prometheus-conf` | Generates `prometheus.yml` from template. |
| `make grafana-conf`    | Generates dashboard JSON files from templates. |
| `make docker-build`    | Builds the Docker images. |
| `make docker-run`      | Starts the containers in the background. |
| `make docker-stop`     | Stops containers and deletes generated config files. |
| `make docker-up`       | Orchestrates the full workflow: generates configs, builds, starts the stack, and streams logs. |
| `make docker-logs`     | Streams real-time logs. |


## Accessing the Interfaces

- **Grafana**: Exposed publicly via `http://localhost:{GRAFANA_PORT}`.
- **Prometheus**: Accessible internally via the Docker network.

