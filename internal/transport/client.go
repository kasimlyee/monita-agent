// Package transport handles authenticated, compressed HTTP pushes to the Collector.
package transport

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/kasimlyee/monita-agent/internal/auth"
	"github.com/kasimlyee/monita-agent/internal/buffer"
	"github.com/kasimlyee/monita-agent/internal/config"
	"github.com/kasimlyee/monita-agent/internal/logs"
	"github.com/kasimlyee/monita-agent/internal/metrics"
)

// Sentinel errors returned by push methods so callers can apply specific logic.
var (
	// ErrUnauthorized is returned on HTTP 401. The push loop uses consecutive
	// counts of this error to distinguish clock-skew from token revocation.
	ErrUnauthorized = errors.New("unauthorized (401) — check clock sync or token validity")

	// ErrFingerprintMismatch is returned on HTTP 403 after a fingerprint no-match.
	// Pushes will be rejected until an operator re-approves via the dashboard.
	ErrFingerprintMismatch = errors.New("fingerprint no-match (403) — dashboard re-approval required")
)

// pushResponse is the shape we look for in every successful push response body.
type pushResponse struct {
	RotationRequired bool `json:"rotation_required"`
}

// Client pushes metrics and log batches to the Collector.
type Client struct {
	cfg             *config.Config
	fingerprintHash string
	http            *http.Client
	zstdEnc         *zstd.Encoder // nil → gzip fallback

	// token and signingKey may be updated atomically on rotation.
	mu         sync.RWMutex
	token      string
	signingKey string
}

// New creates a Client. Returns an error if cert_pin is configured but malformed.
func New(cfg *config.Config, fingerprintHash string) (*Client, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13, // PROTOCOL.md §1: TLS 1.3 only, no downgrade
	}

	if cfg.CertPin != "" {
		pin, err := hex.DecodeString(cfg.CertPin)
		if err != nil {
			return nil, fmt.Errorf("cert_pin must be a hex-encoded SHA-256 digest: %w", err)
		}
		if len(pin) != sha256.Size {
			return nil, fmt.Errorf("cert_pin: expected %d bytes, got %d", sha256.Size, len(pin))
		}
		// PROTOCOL.md §1: pin is SHA-256 of the Collector's DER-encoded leaf cert.
		tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("server presented no certificates")
			}
			got := sha256.Sum256(rawCerts[0])
			if !bytes.Equal(got[:], pin) {
				return fmt.Errorf("certificate pin mismatch — possible MITM or cert rotation")
			}
			return nil
		}
	}

	t := &http.Transport{
		TLSClientConfig:   tlsCfg,
		ForceAttemptHTTP2: true,
	}

	enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		// zstd init failure is non-fatal: gzip fallback is always available.
		fmt.Fprintf(os.Stderr, "level=warn msg=\"zstd init failed, falling back to gzip\" err=%q\n", err)
		enc = nil
	}

	return &Client{
		cfg:             cfg,
		fingerprintHash: fingerprintHash,
		http:            &http.Client{Transport: t, Timeout: 30 * time.Second},
		zstdEnc:         enc,
		token:           cfg.Token,
		signingKey:      cfg.SigningKey,
	}, nil
}

// RegisterFingerprint sends the one-time fingerprint registration per PROTOCOL.md §3.4.
func (c *Client) RegisterFingerprint(ctx context.Context) error {
	type regBody struct {
		AgentID         string          `json:"agent_id"`
		FingerprintHash string          `json:"fingerprint_hash"`
		Components      map[string]bool `json:"components"`
	}
	body, err := json.Marshal(regBody{
		AgentID:         c.cfg.AgentID,
		FingerprintHash: c.fingerprintHash,
		// Presence-only booleans — raw hardware values never leave the host.
		Components: map[string]bool{
			"machine_id":       true,
			"primary_mac":      true,
			"root_volume_uuid": true,
		},
	})
	if err != nil {
		return fmt.Errorf("marshal fingerprint: %w", err)
	}
	return c.postRaw(ctx, "/v1/agents/self/fingerprint", body, "application/json")
}

// RotateToken calls POST /v1/agents/self/rotate (PROTOCOL.md §5) when the
// Collector signals rotation_required. The new credentials replace the in-memory
// token and signing_key. The caller should persist the updated values to config.yaml.
func (c *Client) RotateToken(ctx context.Context) error {
	c.mu.RLock()
	tok, key := c.token, c.signingKey
	c.mu.RUnlock()

	body := []byte(`{}`)
	hdrs, err := auth.Headers(tok, key, c.fingerprintHash, body)
	if err != nil {
		return fmt.Errorf("build auth headers for rotate: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.cfg.CollectorURL+"/v1/agents/self/rotate", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build rotate request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("rotate http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("rotate: unexpected status %d", resp.StatusCode)
	}

	var result struct {
		Token      string `json:"token"`
		SigningKey  string `json:"signing_key"`
		ExpiresAt  int64  `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode rotate response: %w", err)
	}
	if result.Token == "" || result.SigningKey == "" {
		return fmt.Errorf("rotate response missing token or signing_key")
	}

	c.mu.Lock()
	c.token = result.Token
	c.signingKey = result.SigningKey
	c.mu.Unlock()

	if err := c.cfg.UpdateCredentials(result.Token, result.SigningKey); err != nil {
		fmt.Fprintf(os.Stderr, "level=error msg=\"token rotated in memory but config.yaml write failed — update manually\" err=%q expires_at=%d\n", err, result.ExpiresAt)
	} else {
		fmt.Fprintf(os.Stderr, "level=info msg=\"token rotated and config.yaml updated\" expires_at=%d\n", result.ExpiresAt)
	}
	return nil
}

// metricsBatch matches PROTOCOL.md §3.2.
type metricsBatch struct {
	AgentID string          `json:"agent_id"`
	Points  []metrics.Point `json:"points"`
}

// PushMetrics compresses and sends a metrics batch.
// Returns (ok, rotationRequired, err). err is ErrUnauthorized on 401,
// ErrFingerprintMismatch on 403.
func (c *Client) PushMetrics(ctx context.Context, pts []metrics.Point) (ok bool, rotReq bool, err error) {
	payload, err := json.Marshal(metricsBatch{AgentID: c.cfg.AgentID, Points: pts})
	if err != nil {
		return false, false, fmt.Errorf("marshal metrics batch: %w", err)
	}
	return c.push(ctx, "/v1/metrics", payload)
}

// logsBatch matches PROTOCOL.md §3.3.
type logsBatch struct {
	AgentID string       `json:"agent_id"`
	Entries []logs.Entry `json:"entries"`
}

// PushLogs compresses and sends a logs batch.
// Same return semantics as PushMetrics.
func (c *Client) PushLogs(ctx context.Context, entries []logs.Entry) (ok bool, rotReq bool, err error) {
	payload, err := json.Marshal(logsBatch{AgentID: c.cfg.AgentID, Entries: entries})
	if err != nil {
		return false, false, fmt.Errorf("marshal logs batch: %w", err)
	}
	return c.push(ctx, "/v1/logs", payload)
}

// push is the shared send path for both /v1/metrics and /v1/logs.
func (c *Client) push(ctx context.Context, path string, payload []byte) (ok bool, rotReq bool, err error) {
	compressed, encoding, err := c.compress(payload)
	if err != nil {
		return false, false, fmt.Errorf("compress: %w", err)
	}

	c.mu.RLock()
	tok, key := c.token, c.signingKey
	c.mu.RUnlock()

	hdrs, err := auth.Headers(tok, key, c.fingerprintHash, compressed)
	if err != nil {
		return false, false, fmt.Errorf("build auth headers: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.cfg.CollectorURL+path, bytes.NewReader(compressed))
	if err != nil {
		return false, false, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", encoding)
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return false, false, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		io.Copy(io.Discard, resp.Body)
		return false, false, ErrUnauthorized
	case http.StatusForbidden:
		io.Copy(io.Discard, resp.Body)
		return false, false, ErrFingerprintMismatch
	}

	var pr pushResponse
	// Best-effort parse: if the body is malformed we still check the status code.
	json.NewDecoder(resp.Body).Decode(&pr)

	success := resp.StatusCode >= 200 && resp.StatusCode < 300
	return success, pr.RotationRequired, nil
}

// RunPushLoop drains the metrics channel, batches by interval or max size,
// and pushes with adaptive backoff. Failed batches go to the durable buffer.
// On repeated 401s the loop enters buffer-only mode per SPEC.md §9.
func (c *Client) RunPushLoop(ctx context.Context, buf *buffer.Buffer, metricsCh <-chan []metrics.Point) {
	bo := newBackoff(c.cfg.PushInterval.Duration, 300*time.Second)
	ticker := time.NewTicker(bo.Current())
	defer ticker.Stop()

	var pending []metrics.Point
	authFails := 0  // consecutive 401 count — used for clock-skew detection
	revoked := false // true after too many consecutive 401s → buffer-only mode

	store := func(batch []metrics.Point) {
		payload, _ := json.Marshal(metricsBatch{AgentID: c.cfg.AgentID, Points: batch})
		if err := buf.Store(buffer.Entry{Kind: buffer.KindMetrics, Payload: payload}); err != nil {
			fmt.Fprintf(os.Stderr, "level=warn msg=\"metrics batch dropped, buffer write failed (disk full?)\" err=%q\n", err)
		}
	}

	flush := func() {
		if len(pending) == 0 {
			if !revoked {
				c.drainMetricsBuffer(ctx, buf)
			}
			return
		}

		batch := pending
		pending = nil

		if revoked {
			store(batch)
			return
		}

		ok, rotReq, err := c.PushMetrics(ctx, batch)
		if rotReq {
			if rotErr := c.RotateToken(ctx); rotErr != nil {
				fmt.Fprintf(os.Stderr, "level=error msg=\"token rotation failed\" err=%q\n", rotErr)
			}
		}

		if errors.Is(err, ErrUnauthorized) {
			authFails++
			store(batch)
			if authFails == 3 {
				// SPEC.md §9: surface clear clock-sync message on repeated 401s.
				fmt.Fprintf(os.Stderr, "level=error msg=\"repeated 401s — verify NTP clock sync and token validity\"\n")
			}
			if authFails >= 10 {
				revoked = true
				fmt.Fprintf(os.Stderr, "level=error msg=\"entering buffer-only mode after repeated 401s — re-provision token to resume pushing\"\n")
			}
			return
		}

		if errors.Is(err, ErrFingerprintMismatch) {
			fmt.Fprintf(os.Stderr, "level=error msg=%q\n", ErrFingerprintMismatch.Error())
			store(batch)
			return
		}

		if err != nil || !ok {
			fmt.Fprintf(os.Stderr, "level=warn msg=\"metrics push failed, buffering\" err=%v\n", err)
			store(batch)
			authFails = 0
			prev := bo.Current()
			next := bo.Fail()
			if next != prev {
				ticker.Reset(next)
				fmt.Fprintf(os.Stderr, "level=info msg=\"backoff\" next_interval=%s\n", next)
			}
			return
		}

		authFails = 0
		if reset := bo.Success(); reset {
			ticker.Reset(bo.Current())
			fmt.Fprintf(os.Stderr, "level=info msg=\"backoff reset\" interval=%s\n", bo.Current())
		}
		c.drainMetricsBuffer(ctx, buf)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case pts := <-metricsCh:
			pending = append(pending, pts...)
			if len(pending) >= c.cfg.MaxBatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// RunLogsLoop mirrors RunPushLoop for /v1/logs with Coalescer dedup.
func (c *Client) RunLogsLoop(ctx context.Context, buf *buffer.Buffer, logsCh <-chan logs.Entry) {
	bo := newBackoff(c.cfg.PushInterval.Duration, 300*time.Second)
	ticker := time.NewTicker(bo.Current())
	defer ticker.Stop()

	var coal logs.Coalescer
	authFails := 0
	revoked := false

	store := func(batch []logs.Entry) {
		payload, _ := json.Marshal(logsBatch{AgentID: c.cfg.AgentID, Entries: batch})
		if err := buf.Store(buffer.Entry{Kind: buffer.KindLogs, Payload: payload}); err != nil {
			fmt.Fprintf(os.Stderr, "level=warn msg=\"logs batch dropped, buffer write failed (disk full?)\" err=%q\n", err)
		}
	}

	flush := func() {
		batch := coal.Flush()
		if len(batch) == 0 {
			if !revoked {
				c.drainLogsBuffer(ctx, buf)
			}
			return
		}

		if revoked {
			store(batch)
			return
		}

		ok, rotReq, err := c.PushLogs(ctx, batch)
		if rotReq {
			if rotErr := c.RotateToken(ctx); rotErr != nil {
				fmt.Fprintf(os.Stderr, "level=error msg=\"token rotation failed\" err=%q\n", rotErr)
			}
		}

		if errors.Is(err, ErrUnauthorized) {
			authFails++
			store(batch)
			if authFails == 3 {
				fmt.Fprintf(os.Stderr, "level=error msg=\"repeated 401s — verify NTP clock sync and token validity\"\n")
			}
			if authFails >= 10 {
				revoked = true
				fmt.Fprintf(os.Stderr, "level=error msg=\"entering buffer-only mode after repeated 401s — re-provision token to resume pushing\"\n")
			}
			return
		}

		if errors.Is(err, ErrFingerprintMismatch) {
			fmt.Fprintf(os.Stderr, "level=error msg=%q\n", ErrFingerprintMismatch.Error())
			store(batch)
			return
		}

		if err != nil || !ok {
			fmt.Fprintf(os.Stderr, "level=warn msg=\"logs push failed, buffering\" err=%v\n", err)
			store(batch)
			authFails = 0
			prev := bo.Current()
			next := bo.Fail()
			if next != prev {
				ticker.Reset(next)
				fmt.Fprintf(os.Stderr, "level=info msg=\"backoff\" next_interval=%s\n", next)
			}
			return
		}

		authFails = 0
		if reset := bo.Success(); reset {
			ticker.Reset(bo.Current())
		}
		c.drainLogsBuffer(ctx, buf)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case e := <-logsCh:
			coal.Add(e)
			if coal.Len() >= c.cfg.MaxBatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// drainMetricsBuffer replays one buffered metrics entry per flush cycle so
// reconnect replay never bursts the full backlog at once (SPEC.md §6).
func (c *Client) drainMetricsBuffer(ctx context.Context, buf *buffer.Buffer) {
	entry, err := buf.NextKind(buffer.KindMetrics)
	if err != nil {
		fmt.Fprintf(os.Stderr, "level=error msg=\"metrics buffer read\" err=%q\n", err)
		return
	}
	if entry == nil {
		return
	}
	var batch metricsBatch
	if err := json.Unmarshal(entry.Payload, &batch); err != nil {
		fmt.Fprintf(os.Stderr, "level=error msg=\"metrics buffer decode, discarding\" err=%q\n", err)
		entry.Ack()
		return
	}
	ok, _, err := c.PushMetrics(ctx, batch.Points)
	if err != nil || !ok {
		return // leave on disk, retry next cycle
	}
	if err := entry.Ack(); err != nil {
		fmt.Fprintf(os.Stderr, "level=error msg=\"metrics buffer ack\" err=%q\n", err)
	}
}

// drainLogsBuffer replays one buffered logs entry per flush cycle.
func (c *Client) drainLogsBuffer(ctx context.Context, buf *buffer.Buffer) {
	entry, err := buf.NextKind(buffer.KindLogs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "level=error msg=\"logs buffer read\" err=%q\n", err)
		return
	}
	if entry == nil {
		return
	}
	var batch logsBatch
	if err := json.Unmarshal(entry.Payload, &batch); err != nil {
		fmt.Fprintf(os.Stderr, "level=error msg=\"logs buffer decode, discarding\" err=%q\n", err)
		entry.Ack()
		return
	}
	ok, _, err := c.PushLogs(ctx, batch.Entries)
	if err != nil || !ok {
		return
	}
	if err := entry.Ack(); err != nil {
		fmt.Fprintf(os.Stderr, "level=error msg=\"logs buffer ack\" err=%q\n", err)
	}
}

// compress returns (compressed bytes, Content-Encoding value, error).
// Prefers zstd per PROTOCOL.md §3.1; falls back to stdlib gzip if the
// zstd encoder failed to initialise.
func (c *Client) compress(data []byte) ([]byte, string, error) {
	if c.zstdEnc != nil {
		return c.zstdEnc.EncodeAll(data, make([]byte, 0, len(data))), "zstd", nil
	}
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		return nil, "", fmt.Errorf("gzip write: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, "", fmt.Errorf("gzip close: %w", err)
	}
	return buf.Bytes(), "gzip", nil
}

// postRaw sends a plain (uncompressed, unauthenticated-body) POST.
// Used only for fingerprint registration which is already bearer-authenticated.
func (c *Client) postRaw(ctx context.Context, path string, body []byte, contentType string) error {
	c.mu.RLock()
	tok := c.token
	c.mu.RUnlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.cfg.CollectorURL+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+tok)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return nil
}