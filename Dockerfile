FROM python:3.14-alpine3.23@sha256:8caa2adfeb414dfe68d8b257f7aea9e205a400521c2b13b2d2e5e731fb8e70e5 AS builder

RUN pip install --root-user-action=ignore --no-cache-dir --upgrade pip \
    && pip install --root-user-action=ignore --no-cache-dir uv

ENV UV_LINK_MODE=copy

WORKDIR /app

RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project --no-dev

COPY . /app

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev


FROM python:3.14-alpine3.23@sha256:8caa2adfeb414dfe68d8b257f7aea9e205a400521c2b13b2d2e5e731fb8e70e5

# Populated by CI from the tag and commit being published; see docker-publish.yml.
# Defaults keep a local `docker build` honest rather than claiming a real release.
ARG VERSION=dev
ARG REVISION=unknown

LABEL org.opencontainers.image.title="NetBox MCP Server" \
      org.opencontainers.image.description="MCP server for NetBox: read-only by default, opt-in write tools via ENABLE_WRITES" \
      org.opencontainers.image.url="https://github.com/z23/netbox-mcp-server" \
      org.opencontainers.image.source="https://github.com/z23/netbox-mcp-server" \
      org.opencontainers.image.documentation="https://github.com/z23/netbox-mcp-server/blob/main/README.md" \
      org.opencontainers.image.vendor="z23" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"
ENV PYTHONUNBUFFERED=1

RUN apk update && apk upgrade --no-cache \
    && apk add --no-cache ca-certificates \
    && addgroup -g 1000 appuser \
    && adduser -D -u 1000 -G appuser appuser

COPY --from=builder --chown=appuser:appuser /app /app

WORKDIR /app

USER appuser

ENV PATH="/app/.venv/bin:$PATH"

EXPOSE 8000

CMD ["netbox-mcp-server"]
