FROM prom/prometheus:latest

WORKDIR /app

COPY entrypoint.sh /app/entrypoint.sh
COPY prometheus.yml /etc/prometheus/prometheus.yml

HEALTHCHECK --interval=10s --timeout=5s --retries=6 --start-period=10s \
  CMD wget -qO- http://localhost:9090/-/ready || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
