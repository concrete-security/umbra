# syntax=docker/dockerfile:1.26.0@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
FROM nginx:1.30.7-alpine3.24@sha256:bef154735288bc38d99fac41ae63730684bcc661503673a04a0f9bc526ba8598

# Pin the complete added package closure. Alpine stable repositories replace
# revisions in place; an unavailable reviewed version must fail closed.
RUN printf '%s\n' '@alpine-security https://dl-cdn.alpinelinux.org/alpine/edge/main' >> /etc/apk/repositories \
    && apk add --no-cache \
      brotli-libs=1.2.1-r0 \
      ca-certificates=20261020-r0 \
      ca-certificates-bundle=20261020-r0 \
      gettext=1.0-r0 \
      gettext-libs=1.0-r0 \
      libcrypto3=3.5.9-r0 \
      libexpat=2.10.0-r0 \
      libgomp=15.2.0-r5 \
      libssl3=3.5.9-r0 \
      libxml2@alpine-security=2.13.9-r3 \
      musl@alpine-security=1.2.6-r6 \
      musl-utils@alpine-security=1.2.6-r6 \
    # The server only serves install.sh; its curl calls run on the client.
    && apk del --no-cache curl libcurl \
    && ! apk info -e curl \
    && ! apk info -e libcurl \
    && rm -f /var/log/apk.log

COPY install.sh /opt/umbra/installer/install.sh.template
COPY nginx.conf.template /etc/nginx/templates/nginx.conf.template
COPY entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
