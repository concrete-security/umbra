# syntax=docker/dockerfile:1.26.0@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
FROM nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10

# Pin the complete added package closure. Alpine stable repositories replace
# revisions in place; an unavailable reviewed version must fail closed.
RUN apk add --no-cache \
      gettext=0.22.5-r0 \
      gettext-libs=0.22.5-r0 \
      libgomp=14.2.0-r4

COPY install.sh /opt/umbra/installer/install.sh.template
COPY nginx.conf.template /etc/nginx/templates/nginx.conf.template
COPY entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
