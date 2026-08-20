# syntax=docker/dockerfile:1.26.0@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
FROM nginx:1.30.4-alpine3.24@sha256:97d490c12ba55b4946b01546d1c3ed324e8d41ab1c9fcb2a616aa470620e5b46

# Pin the complete added package closure. Alpine stable repositories replace
# revisions in place; an unavailable reviewed version must fail closed.
RUN apk add --no-cache \
      certbot=5.6.0-r0 \
      certbot-pyc=5.6.0-r0 \
      gdbm=1.26-r0 \
      gettext=1.0-r0 \
      gettext-libs=1.0-r0 \
      libffi=3.5.2-r1 \
      libgomp=15.2.0-r5 \
      libpanelw=6.6_p20260516-r0 \
      mpdecimal=4.0.1-r0 \
      py3-acme=5.6.0-r0 \
      py3-acme-pyc=5.6.0-r0 \
      py3-certifi=2026.2.25-r1 \
      py3-certifi-pyc=2026.2.25-r1 \
      py3-cffi=2.0.0-r0 \
      py3-cffi-pyc=2.0.0-r0 \
      py3-charset-normalizer=3.4.9-r0 \
      py3-charset-normalizer-pyc=3.4.9-r0 \
      py3-configargparse=1.7.5-r1 \
      py3-configargparse-pyc=1.7.5-r1 \
      py3-configobj=5.0.9-r2 \
      py3-configobj-pyc=5.0.9-r2 \
      py3-cparser=3.0-r1 \
      py3-cparser-pyc=3.0-r1 \
      py3-cryptography=47.0.0-r0 \
      py3-cryptography-pyc=47.0.0-r0 \
      py3-distro=1.9.0-r4 \
      py3-distro-pyc=1.9.0-r4 \
      py3-distutils-extra=2.47-r4 \
      py3-distutils-extra-pyc=2.47-r4 \
      py3-idna=3.16-r0 \
      py3-idna-pyc=3.16-r0 \
      py3-josepy=2.2.0-r0 \
      py3-josepy-pyc=2.2.0-r0 \
      py3-openssl=26.1.0-r0 \
      py3-openssl-pyc=26.1.0-r0 \
      py3-packaging=26.2-r0 \
      py3-packaging-pyc=26.2-r0 \
      py3-parsedatetime=2.6-r9 \
      py3-parsedatetime-pyc=2.6-r9 \
      py3-parsing=3.3.2-r1 \
      py3-parsing-pyc=3.3.2-r1 \
      py3-pyrfc3339=1.1-r11 \
      py3-pyrfc3339-pyc=1.1-r11 \
      py3-requests=2.33.1-r0 \
      py3-requests-pyc=2.33.1-r0 \
      py3-setuptools=82.0.1-r1 \
      py3-setuptools-pyc=82.0.1-r1 \
      py3-typing-extensions=4.15.0-r1 \
      py3-typing-extensions-pyc=4.15.0-r1 \
      py3-tz=2026.2-r0 \
      py3-tz-pyc=2026.2-r0 \
      py3-urllib3=2.7.0-r0 \
      py3-urllib3-pyc=2.7.0-r0 \
      pyc=3.14.7-r1 \
      python3=3.14.7-r1 \
      python3-pyc=3.14.7-r1 \
      python3-pycache-pyc0=3.14.7-r1 \
      readline=8.3.3-r1 \
      sqlite-libs=3.53.2-r0

COPY entrypoint.sh /entrypoint.sh
COPY default.conf.template /etc/nginx/templates/default.conf.template

ENTRYPOINT ["/entrypoint.sh"]
