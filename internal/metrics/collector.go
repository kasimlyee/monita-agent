// Package metrics samples local system metrics via gopsutil.
package metrics

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	psnet "github.com/shirou/gopsutil/v4/net"
)

// Point is a single metric sample, matching PROTOCOL.md §3.2.
type Point struct {
	Metric string            `json:"metric"`
	Value  float64           `json:"value"`
	Labels map[string]string `json:"labels"`
	TS     int64             `json:"ts"`
}

// emptyLabels is shared across all metric points that carry no label keys,
// avoiding a fresh allocation per point per sample tick (AGENT.md §4).
var emptyLabels = map[string]string{}

// Collector samples the enabled metric categories on a fixed interval.
type Collector struct {
	enabled  map[string]bool
	interval time.Duration

	// Label map caches: built lazily, bounded by the number of distinct
	// cores / mounts / interfaces on the host. Never mutated after creation.
	coreLabels  map[int]map[string]string    // core index → {"core": "N"}
	mountLabels map[string]map[string]string // mountpoint → {"mount": "/..."}
	ifaceLabels map[string]map[string]string // interface name → {"iface": "eth0"}
}

func New(enabled []string, interval time.Duration) *Collector {
	m := make(map[string]bool, len(enabled))
	for _, e := range enabled {
		m[e] = true
	}
	return &Collector{
		enabled:     m,
		interval:    interval,
		coreLabels:  make(map[int]map[string]string),
		mountLabels: make(map[string]map[string]string),
		ifaceLabels: make(map[string]map[string]string),
	}
}

// Run samples on every tick and sends batches to out until ctx is cancelled.
func (c *Collector) Run(ctx context.Context, out chan<- []Point) {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pts, err := c.sample(ctx)
			if err != nil {
				fmt.Fprintf(os.Stderr, "level=warn msg=\"metrics sample error\" err=%q\n", err)
				continue
			}
			if len(pts) == 0 {
				continue
			}
			select {
			case out <- pts:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (c *Collector) sample(ctx context.Context) ([]Point, error) {
	now := time.Now().Unix()
	var pts []Point

	if c.enabled["cpu"] {
		perCore, err := cpu.PercentWithContext(ctx, 0, true)
		if err == nil {
			for i, p := range perCore {
				pts = append(pts, Point{
					Metric: "cpu.percent",
					Value:  p,
					Labels: c.coreLabel(i),
					TS:     now,
				})
			}
		}
		agg, err := cpu.PercentWithContext(ctx, 0, false)
		if err == nil && len(agg) > 0 {
			pts = append(pts, Point{
				Metric: "cpu.percent",
				Value:  agg[0],
				Labels: c.coreLabel(-1), // -1 → "all"
				TS:     now,
			})
		}
	}

	if c.enabled["memory"] {
		v, err := mem.VirtualMemoryWithContext(ctx)
		if err == nil {
			pts = append(pts,
				Point{Metric: "mem.used_bytes", Value: float64(v.Used), Labels: emptyLabels, TS: now},
				Point{Metric: "mem.available_bytes", Value: float64(v.Available), Labels: emptyLabels, TS: now},
				Point{Metric: "mem.total_bytes", Value: float64(v.Total), Labels: emptyLabels, TS: now},
			)
		}
	}

	if c.enabled["disk"] {
		partitions, err := disk.PartitionsWithContext(ctx, false)
		if err == nil {
			for _, p := range partitions {
				usage, err := disk.UsageWithContext(ctx, p.Mountpoint)
				if err != nil {
					continue
				}
				ml := c.mountLabel(p.Mountpoint)
				pts = append(pts,
					Point{Metric: "disk.used_bytes", Value: float64(usage.Used), Labels: ml, TS: now},
					Point{Metric: "disk.total_bytes", Value: float64(usage.Total), Labels: ml, TS: now},
					Point{Metric: "disk.percent", Value: usage.UsedPercent, Labels: ml, TS: now},
				)
			}
		}
	}

	if c.enabled["load"] {
		avg, err := load.AvgWithContext(ctx)
		if err == nil {
			pts = append(pts,
				Point{Metric: "load.1", Value: avg.Load1, Labels: emptyLabels, TS: now},
				Point{Metric: "load.5", Value: avg.Load5, Labels: emptyLabels, TS: now},
				Point{Metric: "load.15", Value: avg.Load15, Labels: emptyLabels, TS: now},
			)
		}
	}

	if c.enabled["network"] {
		counters, err := psnet.IOCountersWithContext(ctx, true)
		if err == nil {
			for _, s := range counters {
				il := c.ifaceLabel(s.Name)
				pts = append(pts,
					Point{Metric: "net.bytes_sent", Value: float64(s.BytesSent), Labels: il, TS: now},
					Point{Metric: "net.bytes_recv", Value: float64(s.BytesRecv), Labels: il, TS: now},
				)
			}
		}
	}

	return pts, nil
}

// coreLabel returns a cached {"core": "N"} map. -1 maps to "all".
func (c *Collector) coreLabel(i int) map[string]string {
	if m, ok := c.coreLabels[i]; ok {
		return m
	}
	val := fmt.Sprintf("%d", i)
	if i < 0 {
		val = "all"
	}
	m := map[string]string{"core": val}
	c.coreLabels[i] = m
	return m
}

// mountLabel returns a cached {"mount": mountpoint} map.
func (c *Collector) mountLabel(mp string) map[string]string {
	if m, ok := c.mountLabels[mp]; ok {
		return m
	}
	m := map[string]string{"mount": mp}
	c.mountLabels[mp] = m
	return m
}

// ifaceLabel returns a cached {"iface": name} map.
func (c *Collector) ifaceLabel(name string) map[string]string {
	if m, ok := c.ifaceLabels[name]; ok {
		return m
	}
	m := map[string]string{"iface": name}
	c.ifaceLabels[name] = m
	return m
}