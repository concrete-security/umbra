# Monitoring Stack

This directory provides a fully containerized monitoring stack built on _Prometheus_ and _Grafana_, with the goal of monitoring and assessing our vLLM model.

- **vLLM** exposes a `/metrics` endpoint, which provides detailed runtime metrics about the model.
- **Prometheus** continuously scrapes this endpoint and stores the data as structured time series.
- **Grafana** then displays these metrics using dashboards.
    Two dashboards are available:
    - User overview: TTFT, end-to-end latency, queue waiting time, number of running requests, etc.
    - Machine overview: GPU usage, memory and CPU workload, running/waiting requests, and more.

Everything is configured through a `.env` file and managed using a Makefile.

## Configuration

All dynamic values are defined in `.env`.

Most importantly:

```env
ADMIN_USER=
ADMIN_PASSWORD=

VLLM_TARGET=
SCHEMA=
```
To change the monitored endpoint, simply update `VLLM_TARGET` and `SCHEME`.

## Starting the Monitoring Stack

### Build images

```
make docker-build
```

### Run the stack

```
make docker-run
```

### Stop the stack

```
make docker-stop
```

### Show logs

```
make docker-logs
```

### Start Prometheus + Grafana

```
make docker-up
```

This will:

1. Load `.env`
2. Generate `prometheus.yml` from the template based on .env
3. Stop any existing containers
4. Rebuild the services
5. Start Prometheus & Grafana
6. Stream logs

## Accessing the Interfaces

Only **Grafana** is exposed publicly.

```
http://localhost:{GRAFANA_PORT}
```
