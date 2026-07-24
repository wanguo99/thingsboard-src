FROM python:3.12.11-slim-bookworm AS builder

ARG PIP_INDEX_URL=https://pypi.org/simple
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_INDEX_URL=${PIP_INDEX_URL} \
    PIP_DEFAULT_TIMEOUT=120 \
    PIP_RETRIES=5

WORKDIR /build
COPY pyproject.toml requirements.lock README.md ./
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/pip \
    python -m pip wheel --wheel-dir /wheels -r requirements.lock setuptools==80.9.0 wheel==0.45.1 \
    && python -m pip install --no-index --find-links=/wheels setuptools==80.9.0 wheel==0.45.1 \
    && python -m pip wheel --no-deps --no-build-isolation --wheel-dir /wheels .

FROM python:3.12.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/smart-alarm/bin:$PATH

RUN groupadd --system --gid 10001 smartalarm \
    && useradd --system --uid 10001 --gid smartalarm --home-dir /nonexistent --shell /usr/sbin/nologin smartalarm

COPY --from=builder /wheels /wheels
RUN python -m venv /opt/smart-alarm \
    && /opt/smart-alarm/bin/python -m pip install --no-cache-dir /wheels/*.whl \
    && rm -rf /wheels

COPY migrations /opt/smart-alarm/migrations
USER 10001:10001
WORKDIR /opt/smart-alarm
EXPOSE 6004 9464

ENTRYPOINT ["smart-alarm-bff"]
