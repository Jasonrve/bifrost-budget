FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_SYSTEM_PYTHON=1

WORKDIR /app

RUN pip install --no-cache-dir uv

COPY pyproject.toml README.md ./
COPY src ./src

RUN uv pip install --system --no-cache-dir .

FROM python:3.11-slim AS runtime

ARG VERSION=0.3.6
ARG BUILD_SHA=unknown

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    BIFROST_HOST=0.0.0.0 \
    BIFROST_PORT=8080 \
    BIFROST_MCP_PATH=/mcp \
    BIFROST_TRANSPORT=streamable-http \
    BIFROST_BUILD_SHA=${BUILD_SHA}

LABEL org.opencontainers.image.version=${VERSION} \
      org.opencontainers.image.revision=${BUILD_SHA}

WORKDIR /app

COPY --from=builder /usr/local /usr/local
COPY --from=builder /app /app

EXPOSE 8080

CMD ["python", "-m", "bifrost_budget"]
