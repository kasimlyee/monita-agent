# PROTOCOL.md — Agent ↔ Collector Wire Protocol

> This document is the shared contract between the `monita-agent` and
> `monita-collector` repositories. Neither repo owns it outright —
> both must treat it as a versioned external dependency. **Breaking changes
> here require a protocol version bump (section 6), not a silent change in
> just one repo.**
>
> Vendor this file (or a copy) into both repos under `/docs/PROTOCOL.md` so
> it's reviewable in PRs on either side. Treat divergence between the two
> copies as a bug.

---

## 1. Transport

- **TLS 1.3 only.** No downgrade path.
- **Certificate pinning** (optional, agent-configured): agent config may carry
  a SHA-256 pin of the Collector's leaf cert. If set, agent refuses any other
  cert even if chain-valid.
- **HTTP/2** preferred for connection reuse across frequent pushes.

---

## 2. Identity and authentication

### 2.1 Provisioning (one-time, out of band of normal push traffic)

On `POST /v1/agents` (dashboard-initiated, not agent-initiated), the Collector
issues, exactly once:
- `token` — 256-bit random, base64url. Agent stores this; Collector stores
  only `SHA-256(token)`.
- `signing_key` — separate 256-bit random secret, base64url. Used for HMAC,
  never sent again after this response.

The agent then performs its own one-time **fingerprint registration** (section
4) before its first normal push.

### 2.2 Per-request authentication (every metrics/logs push)

Headers required on every `POST /v1/metrics` and `POST /v1/logs`:

| Header | Value |
|---|---|
| `Authorization` | `Bearer <token>` |
| `X-Timestamp` | Unix seconds, sender's clock |
| `X-Nonce` | 128-bit random, hex, unique per request |
| `X-Signature` | hex HMAC-SHA256, see 2.3 |

### 2.3 Signature computation

```
signed_material = timestamp + "." + nonce + "." + fingerprint_hash + "." + sha256(body)
signature = HMAC-SHA256(signing_key, signed_material)
```

- `fingerprint_hash` — see section 4. Always included, even though it's also
  verified independently against the stored value — it's part of the signed
  material so a tampered fingerprint claim invalidates the signature too.
- `sha256(body)` is hashed first rather than signing the raw body directly, so
  arbitrarily large bodies don't need to be held twice in memory during HMAC
  computation on constrained agent hardware.

### 2.4 Collector-side verification order (fail fast, cheap checks first)

1. Bearer token format well-formed → else `400`
2. Token hash → known, non-revoked, non-expired agent → else `401`
3. `X-Timestamp` within ±120s of server clock → else `401` (replay/clock-skew)
4. `X-Nonce` not seen before for this agent within the timestamp window → else
   `401` (replay)
5. Recompute and compare `X-Signature` → else `401`
6. Compare `fingerprint_hash` against stored value → exact / partial / none
   (section 4.3) — partial and none do **not** block at this layer, they're
   evaluated after auth succeeds, since a partial/no match still needs the
   request accepted (or queued for review) rather than silently dropped.

### 2.5 Rate limiting and payload bounds (collector-enforced, agent must respect)

- Default: 1 request per 5s per agent per endpoint (`metrics`, `logs`
  independent buckets). Configurable collector-side; agent's own batching
  interval (see agent SPEC) should stay comfortably above this floor.
- Max payload size: 1MB **post-decompression**. Enforce the cap before
  decompressing, by capping bytes read from the decompression stream — never
  trust declared `Content-Length`.

---

## 3. Wire format

### 3.1 Compression

- Body is `zstd`-compressed by default. `Content-Encoding: zstd`.
- Agent falls back to `gzip` (`Content-Encoding: gzip`) if zstd isn't
  available on the build target. Collector must support both.

### 3.2 Metrics push body (pre-compression, JSON)

```json
{
  "agent_id": "uuid",
  "points": [
    { "metric": "cpu.percent", "value": 42.1, "labels": {"core": "0"}, "ts": 1750000000 },
    { "metric": "mem.used_bytes", "value": 1048576000, "labels": {}, "ts": 1750000000 }
  ]
}
```

- `points` is a batch — never one point per request (see agent SPEC batching).
- `ts` is unix seconds, agent clock. Collector stores agent-reported `ts` as
  `recorded_at`, separate from server-side `received_at` (clock skew and
  buffered/delayed delivery mean these can legitimately differ).

### 3.3 Logs push body (pre-compression, JSON)

```json
{
  "agent_id": "uuid",
  "entries": [
    {
      "source": "/var/log/app.log",
      "level": "error",
      "message": "connection refused",
      "count": 1,
      "first_seen": 1750000000,
      "last_seen": 1750000000
    }
  ]
}
```

- `count`/`first_seen`/`last_seen` support agent-side dedup coalescing
  (section 5 of agent SPEC) — collector must not assume `count` is always 1.

### 3.4 Fingerprint registration body

```json
{
  "agent_id": "uuid",
  "fingerprint_hash": "sha256-hex",
  "components": { "machine_id": true, "primary_mac": true, "root_volume_uuid": true }
}
```

- `components` is a presence map only (booleans), never the raw values — the
  Collector never needs or receives the actual machine ID/MAC/volume UUID,
  only the resulting hash. This keeps raw hardware identifiers off the wire
  entirely.

---

## 4. Device fingerprinting

### 4.1 Composition (agent-side)

```
fingerprint_hash = SHA-256(machine_id + primary_mac + root_volume_uuid)
```

Computed once at agent first start, cached locally, not recomputed per push.

### 4.2 Registration

Sent once (section 3.4), signed like a normal push, immediately after token
provisioning and before the agent's first metrics/logs push.

### 4.3 Verification tiers (collector-side, evaluated after auth succeeds)

| Result | Action |
|---|---|
| Exact match | Proceed normally |
| Partial match (e.g. machine_id matches, MAC differs) | Accept push, set `fingerprint_drift = true` on agent record, surface as dashboard warning |
| No component matches | Reject push (`403`), fire `security`-type alert event, require manual dashboard re-approval before further pushes are accepted |

---

## 5. Token lifecycle

- **Rotation**: Collector can flag rotation-due in the response body of any
  successful push (`{"rotation_required": true}`). Agent then calls
  `POST /v1/agents/self/rotate` (authenticated with its *current* still-valid
  token) to receive a new token + signing key pair atomically.
- **Revocation**: takes effect on the agent's next request — no session
  state, since auth is fully per-request.
- **Expiry**: `expires_at` on the token; default 1 year, collector-configurable.

---

## 6. Versioning

- All endpoints are under `/v1/...`. A breaking wire-format or auth change
  bumps to `/v2/...` with both versions served in parallel during a deprecation
  window — agents and collector are deployed independently and can't be
  assumed to upgrade in lockstep.
- Non-breaking additions (new optional fields) do not require a version bump,
  but must be additive-only and ignored gracefully by older peers on either
  side.