FROM python:3.12.14-slim-trixie@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea

ARG APP_UID=65532
ARG APP_GID=65532

LABEL org.opencontainers.image.title="netops-helper" \
      org.opencontainers.image.source="https://github.com/radek-cerny-soukr/netops" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/src \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

RUN groupadd --gid "${APP_GID}" netops \
    && useradd --uid "${APP_UID}" --gid "${APP_GID}" --home-dir /nonexistent --shell /usr/sbin/nologin netops

RUN mkdir -p /etc/netops-helper/certs
COPY config/container/tls-pins.json /etc/netops-helper/tls-pins.json
COPY config/container/certs/ /etc/netops-helper/certs/
COPY config/container/ca/ /usr/local/share/ca-certificates/netops-helper/
RUN update-ca-certificates

WORKDIR /app
COPY requirements.lock ./
COPY src ./src
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.lock \
    && python -m pip uninstall -y pip

RUN mkdir -p /var/lib/netops-helper \
    && chown -R "${APP_UID}:${APP_GID}" /var/lib/netops-helper /app

USER ${APP_UID}:${APP_GID}
CMD ["python", "-m", "netops_helper.idle"]
HEALTHCHECK --interval=60s --timeout=10s --start-period=10s --retries=3 \
  CMD ["python", "-m", "netops_helper.selftest"]
