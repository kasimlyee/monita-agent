package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration wraps time.Duration to support YAML unmarshaling from strings like "30s".
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalYAML(v *yaml.Node) error {
	dur, err := time.ParseDuration(v.Value)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", v.Value, err)
	}
	d.Duration = dur
	return nil
}

type MetricsConfig struct {
	Enabled  []string `yaml:"enabled"`
	Interval Duration `yaml:"interval"`
}

type LogSource struct {
	Path            string `yaml:"path"`
	LevelFilter     string `yaml:"level_filter"`
	DockerContainer string `yaml:"docker_container"`
}

type LogsConfig struct {
	Sources []LogSource `yaml:"sources"`
}

type RedactConfig struct {
	Enabled  bool     `yaml:"enabled"`
	Patterns []string `yaml:"patterns"`
}

type Config struct {
	CollectorURL string `yaml:"collector_url"`
	AgentID      string `yaml:"agent_id"`
	Token        string `yaml:"token"`
	SigningKey   string `yaml:"signing_key"`
	CertPin      string `yaml:"cert_pin"`

	PushInterval Duration `yaml:"push_interval"`
	MaxBatchSize int      `yaml:"max_batch_size"`
	BufferMaxMB  int      `yaml:"buffer_max_size_mb"`
	BufferMaxAge Duration `yaml:"buffer_max_age"`

	// StateDir holds the buffer directory and fingerprint registration marker.
	// Defaults to /var/lib/monita-agent on Linux.
	StateDir string `yaml:"state_dir"`

	Metrics   MetricsConfig `yaml:"metrics"`
	Logs      LogsConfig    `yaml:"logs"`
	Redaction RedactConfig  `yaml:"redaction"`
}

func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	var cfg Config
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}

	cfg.applyDefaults()

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.PushInterval.Duration == 0 {
		c.PushInterval.Duration = 30 * time.Second
	}
	if c.MaxBatchSize == 0 {
		c.MaxBatchSize = 500
	}
	if c.BufferMaxMB == 0 {
		c.BufferMaxMB = 50
	}
	if c.BufferMaxAge.Duration == 0 {
		c.BufferMaxAge.Duration = 24 * time.Hour
	}
	if c.Metrics.Interval.Duration == 0 {
		c.Metrics.Interval.Duration = 10 * time.Second
	}
	if len(c.Metrics.Enabled) == 0 {
		c.Metrics.Enabled = []string{"cpu", "memory", "disk", "load", "network"}
	}
	if c.StateDir == "" {
		c.StateDir = "/var/lib/monita-agent"
	}
}

func (c *Config) validate() error {
	if c.CollectorURL == "" {
		return fmt.Errorf("collector_url is required")
	}
	if c.AgentID == "" {
		return fmt.Errorf("agent_id is required")
	}
	if c.Token == "" {
		return fmt.Errorf("token is required")
	}
	if c.SigningKey == "" {
		return fmt.Errorf("signing_key is required")
	}
	return nil
}
