FROM prom/prometheus@sha256:49214755b6153f90a597adcbff0252cc61069f8ab69ce8411285cd4a560e8038

WORKDIR /app


COPY entrypoint.sh /app/entrypoint.sh
COPY prometheus.yml /etc/prometheus/prometheus.yml

HEALTHCHECK --interval=10s --timeout=5s --retries=6 --start-period=10s \
  CMD wget -qO- http://localhost:9090/-/ready || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]



