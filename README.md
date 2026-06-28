# monita-agent

A lightweight, static Go binary that runs as a sidecar or systemd service on monitored servers. It collects system metrics, tails log sources, and pushes signed, compressed batches to a [Monita Collector](https://github.com/kasimlyee/monita-collector).

Designed for resource-constrained and cost-sensitive deployments — ARM Graviton, budget EC2, bare metal. Binary is under 10 MB stripped and idles well under 20 MB RSS.

---

## Collector

The agent pushes to any HTTP service that speaks the wire protocol defined in [`PROTOCOL.md`](docs/PROTOCOL.md). That document is the full contract — endpoints, auth, request/response shapes, compression, fingerprinting, and token lifecycle.

[**monita-collector**](https://github.com/SUDS-Tech/monita-collector) is a reference implementation you can self-host. If you want to build your own, `PROTOCOL.md` is all you need — the agent has no opinion on how the receiver is implemented.

---

## Requirements

- A running Monita Collector reachable over HTTPS
- An `agent_id`, `token`, and `signing_key` provisioned via the Collector dashboard
- Linux (amd64 or arm64). macOS/Windows builds compile but fingerprinting is partial.

---

## Deployment

### Docker (recommended)

Copy `docker-compose.example.yml` from this repo and adapt it:

```yaml
services:
  monita-agent:
    image: ghcr.io/kasimlyee/monita-agent:latest
    read_only: true
    user: "65532:65532"          # distroless nonroot uid
    restart: unless-stopped
    volumes:
      - type: bind
        source: /etc/monita-agent/config.yaml
        target: /etc/monita-agent/config.yaml
        read_only: true
      - type: volume
        source: monita-buffer
        target: /var/lib/monita-agent
      # Only needed if tailing Docker container logs:
      # - /var/run/docker.sock:/var/run/docker.sock:ro

volumes:
  monita-buffer:
```

Create `/etc/monita-agent/config.yaml` with your credentials (see [Configuration](#configuration)) and start:

```bash
docker compose up -d
```

### systemd

Download the binary for your arch from the [releases page](https://github.com/kasimlyee/monita-agent/releases):

```bash
# linux/amd64
curl -L https://github.com/kasimlyee/monita-agent/releases/latest/download/monita-agent-linux-amd64 \
  -o /usr/local/bin/monita-agent && chmod +x /usr/local/bin/monita-agent

# linux/arm64
curl -L https://github.com/kasimlyee/monita-agent/releases/latest/download/monita-agent-linux-arm64 \
  -o /usr/local/bin/monita-agent && chmod +x /usr/local/bin/monita-agent
```

Create the config and state directories:

```bash
mkdir -p /etc/monita-agent /var/lib/monita-agent
# write your config.yaml (see below)
useradd -r -s /bin/false monita-agent
chown monita-agent:monita-agent /var/lib/monita-agent
```

Create `/etc/systemd/system/monita-agent.service`:

```ini
[Unit]
Description=Monita observability agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/monita-agent --config /etc/monita-agent/config.yaml
User=monita-agent
Group=monita-agent
Restart=on-failure
RestartSec=5s
# State dir is the only writable path the agent needs.
ReadWritePaths=/var/lib/monita-agent
ProtectSystem=strict
NoNewPrivileges=true
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now monita-agent
journalctl -u monita-agent -f
```

---

## Configuration

`/etc/monita-agent/config.yaml`:

```yaml
# --- required ---
collector_url: https://monitor.example.com   # Collector base URL
agent_id: <uuid>                             # issued by the Collector dashboard
token: <token>                               # issued by the Collector dashboard
signing_key: <base64url>                     # issued by the Collector dashboard

# --- optional transport ---
cert_pin: ""            # hex SHA-256 of the Collector's TLS leaf cert; leave
                        # empty to rely on normal chain validation
push_interval: 30s      # how often to flush a batch (default 30s)
max_batch_size: 500     # flush early if this many points/entries accumulate
buffer_max_size_mb: 50  # max disk space for the durable buffer (default 50 MB)
buffer_max_age: 24h     # discard buffered data older than this (default 24h)

# --- paths ---
state_dir: /var/lib/monita-agent   # buffer + offset checkpoints (must be writable)

# --- metrics ---
metrics:
  enabled: [cpu, memory, disk, load, network]   # categories to collect
  interval: 10s                                  # sample interval (independent of push_interval)

# --- log tailing ---
logs:
  sources:
    - path: /var/log/app.log      # tail a file
      level_filter: warn          # only forward warn/error/fatal (omit to forward all)
    - docker_container: my-app    # tail a Docker container (requires socket mount)

# --- redaction ---
redaction:
  enabled: true
  patterns:           # additive; applied before log lines touch the buffer
    - 'my_custom_secret_pattern'
```

### Field reference

| Field | Default | Description |
|---|---|---|
| `collector_url` | — | **Required.** HTTPS base URL of the Collector. |
| `agent_id` | — | **Required.** UUID identifying this agent, issued by the Collector. |
| `token` | — | **Required.** Bearer token for push authentication. |
| `signing_key` | — | **Required.** Base64url-encoded 32-byte HMAC key. |
| `cert_pin` | `""` | Hex SHA-256 of the Collector's DER-encoded leaf cert. If set, any other cert is rejected even if chain-valid. |
| `push_interval` | `30s` | Flush interval. Also the base of the adaptive backoff (doubles to 300 s max on repeated failures, resets after 3 consecutive successes). |
| `max_batch_size` | `500` | Flush early when this many metric points or log entries accumulate. |
| `buffer_max_size_mb` | `50` | Max durable buffer size. On overflow, oldest metrics are evicted first; logs only as a last resort. |
| `buffer_max_age` | `24h` | Buffered data older than this is discarded on the next write cycle. |
| `state_dir` | `/var/lib/monita-agent` | Directory for the durable buffer and log-tail offset checkpoints. Must be writable. |
| `metrics.enabled` | `[cpu,memory,disk,load,network]` | Which metric categories to collect. |
| `metrics.interval` | `10s` | How often to sample metrics. Samples accumulate locally until the next push. |
| `logs.sources[].path` | — | Absolute path of a log file to tail. |
| `logs.sources[].level_filter` | `""` | Minimum level to forward (`debug`/`info`/`warn`/`error`/`fatal`). Empty forwards everything. |
| `logs.sources[].docker_container` | — | Name of a Docker container to tail via `/var/run/docker.sock`. Requires the socket to be mounted. |
| `redaction.enabled` | `false` | Enable the redaction pipeline. |
| `redaction.patterns` | `[]` | Additional regex patterns to redact. Added to the built-in set (AWS keys, bearer tokens, common secret assignments). |

---

## Security notes

**Token and signing key** are secrets. Store the config file at `0600` (readable only by the agent user). The agent never logs credential values.

**Cert pinning** (`cert_pin`) locks the agent to a specific Collector certificate. Use it in high-security deployments where MITM by a trusted CA is a concern. You must update the pin whenever the Collector's leaf cert rotates.

**Token rotation** is handled automatically. When the Collector signals `rotation_required` in a push response, the agent calls the rotate endpoint, receives new credentials, and atomically rewrites `config.yaml` with the updated `token` and `signing_key`. The service does not need to be restarted.

**Device fingerprint** is computed as `SHA-256(machine_id + primary_mac + root_volume_uuid)`. Only the hash is sent to the Collector — raw hardware identifiers never leave the host. The fingerprint is registered once at first start and cached via a marker file in `state_dir`.

**Log redaction** runs before log lines touch the local buffer, so secrets never reach disk. The built-in pattern set covers AWS key IDs, bearer tokens, and common `key=value` secret assignments. Add custom patterns via `redaction.patterns`.

---

## Building from source

```bash
git clone https://github.com/kasimlyee/monita-agent
cd monita-agent

# local binary
CGO_ENABLED=0 go build -ldflags="-s -w" -o monita-agent ./cmd/monita-agent

# Docker image (multi-arch via BuildKit)
docker buildx build --platform linux/amd64,linux/arm64 -t monita-agent:latest .
```

Tests:

```bash
go test ./...
go test ./... -bench=. -benchmem
```

---

## License

[MIT](LICENSE)