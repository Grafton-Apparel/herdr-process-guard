package watchdog

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

type Config struct {
	Cleanup           bool    `json:"cleanup"`
	PollSeconds       int     `json:"poll_seconds"`
	OrphanSeconds     int     `json:"orphan_seconds"`
	CooldownSeconds   int     `json:"cooldown_seconds"`
	ResourceSeconds   int     `json:"resource_seconds"`
	IdleSeconds       int     `json:"idle_seconds"`
	CPUPercent        float64 `json:"cpu_percent"`
	RSSBytes          uint64  `json:"rss_bytes"`
	CPUActivityMillis int64   `json:"cpu_activity_ms"`
	GraceSeconds      int     `json:"grace_seconds"`
	MaxRecords        int     `json:"max_records"`
}

func Defaults() Config {
	return Config{PollSeconds: 30, OrphanSeconds: 1800, CooldownSeconds: 1800, ResourceSeconds: 300, IdleSeconds: 14400, CPUPercent: 100, RSSBytes: 2 << 30, GraceSeconds: 5, MaxRecords: 10000}
}
func (c Config) Poll() time.Duration           { return time.Duration(c.PollSeconds) * time.Second }
func (c Config) OrphanWindow() time.Duration   { return time.Duration(c.OrphanSeconds) * time.Second }
func (c Config) Cooldown() time.Duration       { return time.Duration(c.CooldownSeconds) * time.Second }
func (c Config) ResourceWindow() time.Duration { return time.Duration(c.ResourceSeconds) * time.Second }
func (c Config) IdleWindow() time.Duration     { return time.Duration(c.IdleSeconds) * time.Second }
func (c Config) Validate() error {
	if c.PollSeconds < 5 || c.PollSeconds > 300 || c.OrphanSeconds < 1800 || c.OrphanSeconds > 604800 || c.CooldownSeconds < 60 || c.CooldownSeconds > 86400 || c.ResourceSeconds < 60 || c.ResourceSeconds > 86400 || c.IdleSeconds < 300 || c.IdleSeconds > 604800 || c.CPUPercent <= 0 || c.CPUPercent > 100000 || c.RSSBytes < 1<<20 || c.CPUActivityMillis < 0 || c.CPUActivityMillis > 1000 || c.GraceSeconds < 1 || c.GraceSeconds > 60 || c.MaxRecords < 1 || c.MaxRecords > 100000 {
		return fmt.Errorf("invalid watchdog config: poll 5..300s, orphan 1800..604800s, cooldown 60..86400s, resource 60..86400s, idle 300..604800s, CPU >0..100000%%, RSS >=1MiB, CPU activity 0..1000ms, grace 1..60s, records 1..100000")
	}
	return nil
}
func LoadConfig(path string) (Config, error) {
	c := Defaults()
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 65536))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return c, err
	}
	var extra any
	if err = d.Decode(&extra); err != io.EOF {
		return c, fmt.Errorf("config must contain one JSON object")
	}
	return c, c.Validate()
}
