// Package transport handles authenticated, compressed HTTP pushes to the Collector.
package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/kasimlyee/monita-agent/internal/auth"
	"github.com/kasimlyee/monita-agent/internal/buffer"
	"github.com/kasimlyee/monita-agent/internal/config"
	"github.com/kasimlyee/monita-agent/internal/metrics"
)

// zstdEnc is safe for concurrent EncodeAll calls.
var zstdEnc, _ = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault))

// Client pushes metrics and logs batches to the Collector.
type Client struct {
	cfg             *config.Config
	fingerprintHash string
	http            *http.Client
}

func New(cfg *config.Config, fingerprintHash string) *Client {
	t := &http.Transport{
		ForceAttemptHTTP2: true,
	}
	return &Client{
		cfg:             cfg,
		fingerprintHash: fingerprintHash,
		http: &http.Client{
			Transport: t,
			Timeout:   30 * time.Second,
		},
	}
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
		// Presence-only map — raw values never sent per PROTOCOL.md §3.4.
		Components: map[string]bool{
			"machine_id":       true,
			"primary_mac":      true,
			"root_volume_uuid": true,
		},
	})
	if err != nil {
		return fmt.Errorf("marshal fingerprint: %w", err)
	}

	return c.post(ctx, "/v1/agents/self/fingerprint", body, "application/json", "")
}

// metricsBatch matches PROTOCOL.md §3.2.
type metricsBatch struct {
	AgentID string           `json:"agent_id"`
	Points  []metrics.Point  `json:"points"`
}

// PushMetrics compresses and sends a metrics batch. Returns true if accepted,
// false if the Collector returned a transient error (caller should buffer).
// A rotation_required signal in the response is logged; token rotation is
// handled separately once the rotation flow is implemented.
func (c *Client) PushMetrics(ctx context.Context, pts []metrics.Point) (bool, error) {
	payload, err := json.Marshal(metricsBatch{AgentID: c.cfg.AgentID, Points: pts})
	if err != nil {
		return false, fmt.Errorf("marshal metrics batch: %w", err)
	}
	compressed := zstdEnc.EncodeAll(payload, make([]byte, 0, len(payload)))

	hdrs, err := auth.Headers(c.cfg.Token, c.cfg.SigningKey, c.fingerprintHash, compressed)
	if err != nil {
		return false, fmt.Errorf("build auth headers: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.cfg.CollectorURL+"/v1/metrics", bytes.NewReader(compressed))
	if err != nil {
		return false, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "zstd")
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return false, fmt.Errorf("http: %w", err)
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized {
		// Distinguish clock-skew 401s in the caller by returning the error text.
		return false, fmt.Errorf("push rejected: 401 (check clock sync or token validity)")
	}
	if resp.StatusCode == http.StatusForbidden {
		return false, fmt.Errorf("push rejected: 403 (fingerprint no-match, requires dashboard re-approval)")
	}

	return resp.StatusCode >= 200 && resp.StatusCode < 300, nil
}

// RunPushLoop drains the metrics channel, batches by interval or max size,
// and pushes to the Collector with adaptive backoff on failure.
// Failed batches are written to buf for durable retry.
func (c *Client) RunPushLoop(ctx context.Context, buf *buffer.Buffer, metricsCh <-chan []metrics.Point) {
	baseInterval := c.cfg.PushInterval.Duration
	interval := baseInterval
	const maxInterval = 300 * time.Second
	const backoffFactor = 2
	const resetAfterSuccesses = 3

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var pending []metrics.Point
	consecutiveOK := 0

	flush := func() {
		if len(pending) == 0 {
			// No live batch — try to drain one buffered entry instead.
			c.drainBuffer(ctx, buf)
			return
		}

		batch := pending
		pending = nil

		ok, err := c.PushMetrics(ctx, batch)
		if err != nil || !ok {
			fmt.Fprintf(os.Stderr, "level=warn msg=\"push failed, buffering\" err=%v\n", err)
			payload, _ := json.Marshal(metricsBatch{AgentID: c.cfg.AgentID, Points: batch})
			if bufErr := buf.Store(buffer.Entry{Kind: buffer.KindMetrics, Payload: payload}); bufErr != nil {
				fmt.Fprintf(os.Stderr, "level=error msg=\"buffer store failed\" err=%q\n", bufErr)
			}
			consecutiveOK = 0
			if interval < maxInterval {
				interval = min(interval*backoffFactor, maxInterval)
				ticker.Reset(interval)
				fmt.Fprintf(os.Stderr, "level=info msg=\"backoff\" next_interval=%s\n", interval)
			}
			return
		}

		consecutiveOK++
		if consecutiveOK >= resetAfterSuccesses && interval > baseInterval {
			interval = baseInterval
			ticker.Reset(interval)
			consecutiveOK = 0
			fmt.Fprintf(os.Stderr, "level=info msg=\"backoff reset\" interval=%s\n", interval)
		}
		// On a successful live push, try draining one buffered batch too.
		c.drainBuffer(ctx, buf)
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

// drainBuffer replays one pending buffer entry. Oldest-first, one per flush
// cycle so reconnect replay never bursts the full backlog at once.
func (c *Client) drainBuffer(ctx context.Context, buf *buffer.Buffer) {
	entry, err := buf.Next()
	if err != nil {
		fmt.Fprintf(os.Stderr, "level=error msg=\"buffer read\" err=%q\n", err)
		return
	}
	if entry == nil {
		return
	}

	var batch metricsBatch
	if err := json.Unmarshal(entry.Payload, &batch); err != nil {
		fmt.Fprintf(os.Stderr, "level=error msg=\"buffer decode\" err=%q\n", err)
		entry.Ack() // corrupt entry — discard
		return
	}

	ok, err := c.PushMetrics(ctx, batch.Points)
	if err != nil || !ok {
		fmt.Fprintf(os.Stderr, "level=warn msg=\"buffer replay failed\" err=%v\n", err)
		return // leave on disk, retry next cycle
	}
	if err := entry.Ack(); err != nil {
		fmt.Fprintf(os.Stderr, "level=error msg=\"buffer ack\" err=%q\n", err)
	}
}

// post is a helper for unauthenticated-body endpoints (fingerprint registration).
func (c *Client) post(ctx context.Context, path string, body []byte, contentType, _ string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.cfg.CollectorURL+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)

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
