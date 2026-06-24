package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/kasimlyee/monita-agent/internal/buffer"
	"github.com/kasimlyee/monita-agent/internal/config"
	"github.com/kasimlyee/monita-agent/internal/fingerprint"
	"github.com/kasimlyee/monita-agent/internal/metrics"
	"github.com/kasimlyee/monita-agent/internal/transport"
)

func main() {
	configPath := flag.String("config", "/etc/bastion-agent/config.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "level=crit msg=\"load config\" err=%q\n", err)
		os.Exit(1)
	}

	fpHash, err := fingerprint.Compute()
	if err != nil {
		// Non-fatal: agent can still push, but fingerprint will be empty and the
		// Collector will flag it. Log clearly so the operator can investigate.
		fmt.Fprintf(os.Stderr, "level=error msg=\"fingerprint compute failed\" err=%q\n", err)
		fpHash = ""
	}

	bufDir := filepath.Join(cfg.StateDir, "buffer")
	buf, err := buffer.New(bufDir, cfg.BufferMaxMB, cfg.BufferMaxAge.Duration)
	if err != nil {
		fmt.Fprintf(os.Stderr, "level=crit msg=\"init buffer\" err=%q\n", err)
		os.Exit(1)
	}

	client := transport.New(cfg, fpHash)

	// One-time fingerprint registration: write a marker file once it succeeds so
	// subsequent starts skip the call. The marker lives next to the buffer dir.
	regMarker := filepath.Join(cfg.StateDir, "fingerprint.registered")
	if _, err := os.Stat(regMarker); os.IsNotExist(err) {
		if fpHash != "" {
			if err := client.RegisterFingerprint(context.Background()); err != nil {
				// Not fatal — push loop will still work; the Collector will surface
				// the missing registration as a warning on the dashboard.
				fmt.Fprintf(os.Stderr, "level=error msg=\"fingerprint registration\" err=%q\n", err)
			} else {
				if err := os.WriteFile(regMarker, []byte("ok"), 0o600); err != nil {
					fmt.Fprintf(os.Stderr, "level=warn msg=\"save reg marker\" err=%q\n", err)
				}
			}
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Buffered so the collector goroutine never blocks the sampler.
	metricsCh := make(chan []metrics.Point, 16)

	collector := metrics.New(cfg.Metrics.Enabled, cfg.Metrics.Interval.Duration)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		collector.Run(ctx, metricsCh)
	}()

	go func() {
		defer wg.Done()
		client.RunPushLoop(ctx, buf, metricsCh)
	}()

	wg.Wait()
	fmt.Fprintln(os.Stderr, "level=info msg=\"agent stopped\"")
}