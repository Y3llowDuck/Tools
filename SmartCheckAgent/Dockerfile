# ── Stage 1: compile ─────────────────────────────────────────────────────────
FROM kalilinux/kali-rolling:latest AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip python3-venv python3-dev binutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY requirements.txt .
RUN python3 -m venv /opt/venv && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install -r requirements.txt pyinstaller

COPY . .
RUN /opt/venv/bin/pyinstaller --onefile --name agent agent.py

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM kalilinux/kali-rolling:latest

# Links this image to its source repo on the package's GitHub page.
LABEL org.opencontainers.image.source="https://github.com/Y3llowDuck/SmartCheckAgent"

RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap httpx-toolkit exploitdb curl wget libcap2-bin ca-certificates \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)

RUN useradd --system --create-home --shell /usr/sbin/nologin scagent \
    && mkdir -p /app/data \
    && chown -R scagent:scagent /app/data

WORKDIR /app

COPY --from=builder /build/dist/agent /app/agent
RUN chmod +x /app/agent

USER scagent

# The compiled binary is a PyInstaller --onefile bundle: at startup it
# unpacks to a randomly-named temp dir and resolves default paths relative
# to THAT dir, not /app. Without these, scope.yaml/the DB silently end up
# inside the (ephemeral) unpack dir instead of the bind mounts below.
ENV SMARTCHECK_SCOPE=/app/scope.yaml \
    SMARTCHECK_DATA_DIR=/app/data \
    SMARTCHECK_PLUGINS_DIR=/app/data/plugins

ENTRYPOINT ["/app/agent"]
CMD ["--help"]
