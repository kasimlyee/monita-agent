package logs

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/kasimlyee/monita-agent/internal/redact"
)

// FileTailer tails a log file from a checkpointed byte offset, forwarding
// filtered and redacted lines to a channel. It handles log rotation via
// fsnotify on the parent directory.
type FileTailer struct {
	source      string
	levelFilter string
	offsetDir   string
	redactor    *redact.Redactor
}

func NewFileTailer(source, levelFilter, offsetDir string, r *redact.Redactor) *FileTailer {
	return &FileTailer{
		source:      source,
		levelFilter: levelFilter,
		offsetDir:   offsetDir,
		redactor:    r,
	}
}

// Run blocks until ctx is cancelled, sending log entries to out.
func (t *FileTailer) Run(ctx context.Context, out chan<- Entry) error {
	offsetPath := t.checkpointPath()
	if err := os.MkdirAll(t.offsetDir, 0o700); err != nil {
		return fmt.Errorf("create offset dir: %w", err)
	}

	f, err := t.openAt(t.loadOffset(offsetPath))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("open %s: %w", t.source, err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		if f != nil {
			f.Close()
		}
		return fmt.Errorf("create watcher: %w", err)
	}
	defer watcher.Close()

	// Watch the parent directory so Create events fire when the file is rotated in.
	if watchErr := watcher.Add(filepath.Dir(t.source)); watchErr != nil {
		if f != nil {
			f.Close()
		}
		return fmt.Errorf("watch dir: %w", watchErr)
	}

	var reader *bufio.Reader
	if f != nil {
		reader = bufio.NewReaderSize(f, 64*1024)
	}

	save := func() {
		if f == nil {
			return
		}
		if pos, err := f.Seek(0, io.SeekCurrent); err == nil {
			t.saveOffset(offsetPath, pos)
		}
	}

	drain := func() {
		if reader == nil {
			return
		}
		for {
			line, err := reader.ReadString('\n')
			if line != "" {
				line = strings.TrimRight(line, "\r\n")
				if line != "" && PassesFilter(line, t.levelFilter) {
					now := time.Now().Unix()
					select {
					case out <- Entry{
						Source:    t.source,
						Level:     ExtractLevel(line),
						Message:   t.redactor.Redact(line),
						Count:     1,
						FirstSeen: now,
						LastSeen:  now,
					}:
					case <-ctx.Done():
						return
					}
				}
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "level=warn msg=\"log read\" source=%q err=%q\n", t.source, err)
				break
			}
		}
		save()
	}

	drain() // flush anything written since last checkpoint

	for {
		select {
		case <-ctx.Done():
			save()
			if f != nil {
				f.Close()
			}
			return nil

		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			if event.Name != t.source {
				continue
			}
			switch {
			case event.Has(fsnotify.Write):
				drain()

			case event.Has(fsnotify.Create):
				// File rotated: reopen from the start.
				save()
				if f != nil {
					f.Close()
				}
				f, err = os.Open(t.source)
				if err != nil {
					f, reader = nil, nil
					fmt.Fprintf(os.Stderr, "level=warn msg=\"reopen after rotation\" source=%q err=%q\n", t.source, err)
					continue
				}
				reader = bufio.NewReaderSize(f, 64*1024)
				t.saveOffset(offsetPath, 0)
				drain()

			case event.Has(fsnotify.Remove), event.Has(fsnotify.Rename):
				save()
				if f != nil {
					f.Close()
					f, reader = nil, nil
				}
			}

		case werr, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			fmt.Fprintf(os.Stderr, "level=warn msg=\"watcher error\" source=%q err=%q\n", t.source, werr)
		}
	}
}

func (t *FileTailer) openAt(offset int64) (*os.File, error) {
	f, err := os.Open(t.source)
	if err != nil {
		return nil, err
	}
	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			f.Seek(0, io.SeekStart) //nolint:errcheck
		}
	}
	return f, nil
}

func (t *FileTailer) checkpointPath() string {
	h := sha256.Sum256([]byte(t.source))
	return filepath.Join(t.offsetDir, hex.EncodeToString(h[:])+".offset")
}

func (t *FileTailer) loadOffset(path string) int64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func (t *FileTailer) saveOffset(path string, offset int64) {
	_ = os.WriteFile(path, []byte(strconv.FormatInt(offset, 10)), 0o600)
}