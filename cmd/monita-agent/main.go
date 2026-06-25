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
	"github.com/kasimlyee/monita-agent/internal/logs"
	"github.com/kasimlyee/monita-agent/internal/metrics"
	"github.com/kasimlyee/monita-agent/internal/redact"
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
		fmt.Fprintf(os.Stderr, "level=error msg=\"fingerprint compute failed\" err=%q\n", err)
		fpHash = ""
	}

	bufDir := filepath.Join(cfg.StateDir, "buffer")
	buf, err := buffer.New(bufDir, cfg.BufferMaxMB, cfg.BufferMaxAge.Duration)
	if err != nil {
		fmt.Fprintf(os.Stderr, "level=crit msg=\"init buffer\" err=%q\n", err)
		os.Exit(1)
	}

	client, err := transport.New(cfg, fpHash)
	if err != nil {
		fmt.Fprintf(os.Stderr, "level=crit msg=\"init transport\" err=%q\n", err)
		os.Exit(1)
	}

	// One-time fingerprint registration.
	regMarker := filepath.Join(cfg.StateDir, "fingerprint.registered")
	if _, err := os.Stat(regMarker); os.IsNotExist(err) {
		if fpHash != "" {
			if err := client.RegisterFingerprint(context.Background()); err != nil {
				fmt.Fprintf(os.Stderr, "level=error msg=\"fingerprint registration\" err=%q\n", err)
			} else {
				if err := os.WriteFile(regMarker, []byte("ok"), 0o600); err != nil {
					fmt.Fprintf(os.Stderr, "level=warn msg=\"save reg marker\" err=%q\n", err)
				}
			}
		}
	}

	redactor, err := redact.New(cfg.Redaction.Patterns)
	if err != nil {
		fmt.Fprintf(os.Stderr, "level=crit msg=\"build redactor\" err=%q\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	metricsCh := make(chan []metrics.Point, 16)
	// Buffered so slow tailers don't block each other; sized to one push cycle's
	// worth of entries across all sources.
	logsCh := make(chan logs.Entry, 512)

	offsetDir := filepath.Join(cfg.StateDir, "offsets")

	var wg sync.WaitGroup

	// Metrics sampler.
	wg.Add(1)
	go func() {
		defer wg.Done()
		metrics.New(cfg.Metrics.Enabled, cfg.Metrics.Interval.Duration).Run(ctx, metricsCh)
	}()

	// One goroutine per log source.
	if cfg.Redaction.Enabled || len(cfg.Logs.Sources) > 0 {
		for _, src := range cfg.Logs.Sources {
			src := src // capture
			switch {
			case src.Path != "":
				wg.Add(1)
				go func() {
					defer wg.Done()
					t := logs.NewFileTailer(src.Path, src.LevelFilter, offsetDir, redactor)
					if err := t.Run(ctx, logsCh); err != nil {
						fmt.Fprintf(os.Stderr, "level=error msg=\"file tailer\" source=%q err=%q\n", src.Path, err)
					}
				}()

			case src.DockerContainer != "":
				wg.Add(1)
				go func() {
					defer wg.Done()
					t := logs.NewDockerTailer(src.DockerContainer, src.LevelFilter, "", offsetDir, redactor)
					if err := t.Run(ctx, logsCh); err != nil {
						fmt.Fprintf(os.Stderr, "level=error msg=\"docker tailer\" container=%q err=%q\n", src.DockerContainer, err)
					}
				}()
			}
		}
	}

	// Push loops.
	wg.Add(2)
	go func() {
		defer wg.Done()
		client.RunPushLoop(ctx, buf, metricsCh)
	}()
	go func() {
		defer wg.Done()
		client.RunLogsLoop(ctx, buf, logsCh)
	}()

	wg.Wait()
	fmt.Fprintln(os.Stderr, "level=info msg=\"agent stopped\"")
}