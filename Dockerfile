FROM python:3.14.10-slim-trixie AS tailwind

ARG TARGETARCH
ENV TAILWIND_VERSION=4.3.5

WORKDIR /build

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && case "${TARGETARCH:-amd64}" in \
        amd64) TW_ARCH="x64" ;; \
        arm64) TW_ARCH="arm64" ;; \
        *) echo "Unsupported architecture: ${TARGETARCH}" && exit 1 ;; \
       esac \
    && curl -fsSL "https://github.com/tailwindlabs/tailwindcss/releases/download/v${TAILWIND_VERSION}/tailwindcss-linux-${TW_ARCH}" -o /usr/local/bin/tailwindcss \
    && chmod +x /usr/local/bin/tailwindcss

COPY app/web/static/css/input.css ./app/web/static/css/input.css
COPY app/web/templates ./app/web/templates

RUN tailwindcss -i ./app/web/static/css/input.css -o ./app/web/static/css/app.css --minify


FROM python:3.14.10-slim-trixie AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --require-hashes -r requirements.txt

COPY app ./app
COPY --from=tailwind /build/app/web/static/css/app.css ./app/web/static/css/app.css

RUN useradd --create-home --shell /usr/sbin/nologin appuser \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]


FROM runtime AS dev

USER root

COPY requirements-dev.txt pyproject.toml ./
RUN pip install --require-hashes -r requirements-dev.txt

COPY tests ./tests
RUN chown -R appuser:appuser /app

USER appuser
