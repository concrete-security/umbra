# syntax=docker/dockerfile:1.26.0@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
FROM nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10

# Pin the complete added package closure. Alpine stable repositories replace
# revisions in place; an unavailable reviewed version must fail closed.
RUN apk add --no-cache \
      certbot=3.0.1-r0 \
      certbot-pyc=3.0.1-r0 \
      gdbm=1.24-r0 \
      gettext=0.22.5-r0 \
      gettext-libs=0.22.5-r0 \
      libcrypto3=3.3.7-r0 \
      libffi=3.4.7-r0 \
      libgcc=14.2.0-r4 \
      libgomp=14.2.0-r4 \
      libpanelw=6.5_p20241006-r3 \
      libssl3=3.3.7-r0 \
      libstdc++=14.2.0-r4 \
      mpdecimal=4.0.0-r0 \
      openssl=3.3.7-r0 \
      py3-acme=3.0.1-r0 \
      py3-acme-pyc=3.0.1-r0 \
      py3-certifi=2024.8.30-r0 \
      py3-certifi-pyc=2024.8.30-r0 \
      py3-cffi=1.17.1-r1 \
      py3-cffi-pyc=1.17.1-r1 \
      py3-charset-normalizer=3.4.0-r0 \
      py3-charset-normalizer-pyc=3.4.0-r0 \
      py3-configargparse=1.7-r1 \
      py3-configargparse-pyc=1.7-r1 \
      py3-configobj=5.0.9-r0 \
      py3-configobj-pyc=5.0.9-r0 \
      py3-cparser=2.22-r1 \
      py3-cparser-pyc=2.22-r1 \
      py3-cryptography=44.0.0-r0 \
      py3-cryptography-pyc=44.0.0-r0 \
      py3-distro=1.9.0-r2 \
      py3-distro-pyc=1.9.0-r2 \
      py3-distutils-extra=2.47-r3 \
      py3-distutils-extra-pyc=2.47-r3 \
      py3-future=1.0.0-r1 \
      py3-future-pyc=1.0.0-r1 \
      py3-idna=3.10-r0 \
      py3-idna-pyc=3.10-r0 \
      py3-josepy=1.14.0-r1 \
      py3-josepy-pyc=1.14.0-r1 \
      py3-openssl=24.1.0-r1 \
      py3-openssl-pyc=24.1.0-r1 \
      py3-packaging=24.2-r0 \
      py3-packaging-pyc=24.2-r0 \
      py3-parsedatetime=2.6-r6 \
      py3-parsedatetime-pyc=2.6-r6 \
      py3-parsing=3.1.4-r0 \
      py3-parsing-pyc=3.1.4-r0 \
      py3-pyrfc3339=1.1-r9 \
      py3-pyrfc3339-pyc=1.1-r9 \
      py3-requests=2.33.1-r0 \
      py3-requests-pyc=2.33.1-r0 \
      py3-setuptools=70.3.0-r0 \
      py3-setuptools-pyc=70.3.0-r0 \
      py3-six=1.16.0-r9 \
      py3-six-pyc=1.16.0-r9 \
      py3-tz=2026.2-r0 \
      py3-tz-pyc=2026.2-r0 \
      py3-urllib3=1.26.20-r1 \
      py3-urllib3-pyc=1.26.20-r1 \
      pyc=3.12.13-r0 \
      python3=3.12.13-r0 \
      python3-pyc=3.12.13-r0 \
      python3-pycache-pyc0=3.12.13-r0 \
      readline=8.2.13-r0 \
      sqlite-libs=3.48.0-r4

COPY entrypoint.sh /entrypoint.sh
COPY default.conf.template /etc/nginx/templates/default.conf.template

ENTRYPOINT ["/entrypoint.sh"]
