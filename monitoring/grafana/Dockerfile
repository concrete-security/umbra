FROM grafana/grafana@sha256:f83f232953e417edb9a450a82462386de014631a31d5be402d9029b09f93408d

WORKDIR /app

COPY provisioning /etc/grafana/provisioning

HEALTHCHECK --interval=30s --timeout=3s --start-period=45s --retries=5 \
  CMD curl -fsS http://localhost:4000/api/health | grep -q '"database":"ok"'
