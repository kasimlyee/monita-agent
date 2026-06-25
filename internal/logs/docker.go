package logs

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kasimlyee/monita-agent/internal/redact"
)

// DockerTailer streams logs from a named container via the Docker socket.
// It needs /var/run/docker.sock mounted (opt-in per AGENT.md §5).
//
// Docker log frames are prefixed with an 8-byte header:
//
//	[stream_type(1)] [zero(3)] [length_big_endian(4)]
//
// stream_type: 1=stdout, 2=stderr.
type DockerTailer struct {
	container   string
	levelFilter string
	socketPath  string
	offsetDir   string
	redactor    *redact.Redactor
}

func NewDockerTailer(container, levelFilter, socketPath, offsetDir string, r *redact.Redactor) *DockerTailer {
	if socketPath == "" {
		socketPath = "/var/run/docker.sock"
	}
	return &DockerTailer{
		container:   container,
		levelFilter: levelFilter,
		socketPath:  socketPath,
		offsetDir:   offsetDir,
		redactor:    r,
	}
}

func (t *DockerTailer) Run(ctx context.Context, out chan<- Entry) error {
	if err := os.MkdirAll(t.offsetDir, 0o700); err != nil {
		return fmt.Errorf("create offset dir: %w", err)
	}

	since := t.loadSince()

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", t.socketPath)
			},
		},
	}

	url := fmt.Sprintf("http://localhost/containers/%s/logs?follow=true&stdout=true&stderr=true&timestamps=true&since=%d",
		t.container, since)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build docker logs request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("docker logs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("docker logs: unexpected status %d", resp.StatusCode)
	}

	source := "docker:" + t.container
	br := bufio.NewReaderSize(resp.Body, 64*1024)
	var hdr [8]byte

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return nil // stream ended
			}
			return fmt.Errorf("read docker frame header: %w", err)
		}

		size := binary.BigEndian.Uint32(hdr[4:])
		if size == 0 {
			continue
		}

		payload := make([]byte, size)
		if _, err := io.ReadFull(br, payload); err != nil {
			return fmt.Errorf("read docker frame payload: %w", err)
		}

		line := strings.TrimRight(string(payload), "\r\n")

		// Docker log lines are prefixed with an RFC3339Nano timestamp when
		// timestamps=true. Parse and strip it to get the actual message.
		ts, msg := splitDockerTimestamp(line)
		if msg == "" {
			continue
		}

		if !PassesFilter(msg, t.levelFilter) {
			continue
		}

		t.saveSince(ts)

		now := time.Now().Unix()
		select {
		case out <- Entry{
			Source:    source,
			Level:     ExtractLevel(msg),
			Message:   t.redactor.Redact(msg),
			Count:     1,
			FirstSeen: now,
			LastSeen:  now,
		}:
		case <-ctx.Done():
			return nil
		}
	}
}

// splitDockerTimestamp separates "2006-01-02T15:04:05.999999999Z message" into
// a unix timestamp and the message body. If no timestamp prefix is found, ts=0
// and the whole line is the message.
func splitDockerTimestamp(line string) (ts int64, msg string) {
	tStr, rest, ok := strings.Cut(line, " ")
	if !ok {
		return 0, line
	}
	t, err := time.Parse(time.RFC3339Nano, tStr)
	if err != nil {
		return 0, line
	}
	return t.Unix(), strings.TrimLeft(rest, " ")
}

func (t *DockerTailer) sincePath() string {
	return filepath.Join(t.offsetDir, "docker_"+t.container+".since")
}

func (t *DockerTailer) loadSince() int64 {
	data, err := os.ReadFile(t.sincePath())
	if err != nil {
		return 0
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func (t *DockerTailer) saveSince(ts int64) {
	if ts <= 0 {
		return
	}
	_ = os.WriteFile(t.sincePath(), []byte(strconv.FormatInt(ts, 10)), 0o600)
}