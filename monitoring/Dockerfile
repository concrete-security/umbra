FROM prom/prometheus:latest

COPY prometheus.yml /etc/prometheus/prometheus.yml
COPY entrypoint.sh /app/entrypoint.sh

HEALTHCHECK --interval=10s --timeout=5s --retries=6 --start-period=10s \
  CMD wget -qO- http://localhost:9090/-/ready || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
