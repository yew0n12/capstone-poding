FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /home/yw/poding

ARG TARGETARCH=arm64
ARG KUBECTL_VERSION=v1.30.1

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates tar gzip \
    && curl -fsSL "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl" -o /usr/local/bin/kubectl \
    && chmod +x /usr/local/bin/kubectl \
    && HUBBLE_VERSION="$(curl -fsSL https://raw.githubusercontent.com/cilium/hubble/main/stable.txt)" \
    && curl -L --fail --output /tmp/hubble.tar.gz "https://github.com/cilium/hubble/releases/download/${HUBBLE_VERSION}/hubble-linux-${TARGETARCH}.tar.gz" \
    && tar -xzf /tmp/hubble.tar.gz -C /usr/local/bin hubble \
    && chmod +x /usr/local/bin/hubble \
    && rm -f /tmp/hubble.tar.gz \
    && apt-get purge -y --auto-remove curl \
    && rm -rf /var/lib/apt/lists/*

COPY . /home/yw/poding

RUN if [ -f requirements.txt ]; then pip install -r requirements.txt; fi \
    && python -m pip install pyyaml

CMD ["python3", "live/live_pipeline.py"]
