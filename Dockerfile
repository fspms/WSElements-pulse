# syntax=docker/dockerfile:1
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir build && python -m build --wheel --outdir /dist

FROM python:3.12-slim
LABEL org.opencontainers.image.title="WSElements-pulse collector" \
      org.opencontainers.image.description="Unofficial community collector for WithSecure Elements API data" \
      org.opencontainers.image.licenses="MIT"
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1
COPY --from=build /dist/*.whl /tmp/
RUN pip install /tmp/*.whl && rm -f /tmp/*.whl \
    && useradd --system --uid 10001 --no-create-home pulse
USER 10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4)"]
ENTRYPOINT ["elements-pulse"]
CMD ["run"]
