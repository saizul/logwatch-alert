FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    LOGWATCH_ALERT_CONFIG=/config/config.yaml \
    LOGWATCH_ALERT_HEARTBEAT=/tmp/logwatch-alert.heartbeat
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
# The "adm" group (gid 4 on Debian/Ubuntu) can read most files in /var/log.
RUN pip install . \
    && useradd --system --uid 10001 --no-create-home --groups adm app \
    && mkdir -p /config \
    && rm -rf /app/build
USER app
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD ["logwatch-alert", "healthcheck", "--max-age", "120"]
ENTRYPOINT ["logwatch-alert"]
CMD ["run"]
