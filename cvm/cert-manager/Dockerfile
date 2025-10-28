# Combined Nginx and Certificate Manager Dockerfile

# nginx:1.29-alpine
FROM nginx@sha256:61e01287e546aac28a3f56839c136b31f590273f3b41187a36f46f6a03bbfe22

# ghcr.io/astral-sh/uv:0.9.5
COPY --from=ghcr.io/astral-sh/uv@sha256:f459f6f73a8c4ef5d69f4e6fbbdb8af751d6fa40ec34b39a1ab469acd6e289b7 /uv /uvx /bin/

EXPOSE 80 443

# TODO: thing about reproducible build
# Install Python and dependencies
RUN apk add --no-cache supervisor

# Create app directory
WORKDIR /app

# Install Python dependencies
COPY pyproject.toml /app/
COPY uv.lock /app/
RUN uv sync --locked --no-cache

# Copy app files
COPY entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh
COPY cert_manager.py /app/
COPY nginx_conf /app/nginx_conf
COPY proc_logger.py /app/

# Setup base nginx config
COPY nginx_conf/base.conf /etc/nginx/conf.d/default.conf

# Create supervisor configuration
RUN mkdir -p /etc/supervisor/conf.d
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Create directories for certificates and ACME challenges
RUN mkdir -p /certs /acme-challenge /var/log/supervisor

# Ensure both nginx and cert manager processes are healthy
HEALTHCHECK --interval=30s --timeout=10s --start-period=120s --retries=3 \
    CMD (curl -f -k https://localhost/health || exit 1) && \
        (ls /etc/nginx/ssl/cert.pem /etc/nginx/ssl/key.pem || exit 1)

# Use supervisor to manage both nginx and cert manager processes
ENTRYPOINT ["/app/entrypoint.sh"]
