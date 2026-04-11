package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
)

// SiteConfig holds per-site flag overrides.
type SiteConfig struct {
	BackupEligible bool `json:"backup_eligible"`
	AutoApprove    bool `json:"auto_approve"`
}

// Config is loaded from ~/.config/linux-id/config.json.
type Config struct {
	Sites map[string]SiteConfig `json:"sites"`
}

func loadConfig() Config {
	home, err := os.UserHomeDir()
	if err != nil {
		return Config{}
	}
	path := filepath.Join(home, ".config", "linux-id", "config.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Printf("config: parse error: %s", err)
		return Config{}
	}
	return cfg
}

// BackupEligible returns true if the given rpId has backup_eligible set in config.
func (c *Config) BackupEligible(rpId string) bool {
	if c.Sites == nil {
		return false
	}
	site, ok := c.Sites[rpId]
	if !ok {
		return false
	}
	return site.BackupEligible
}

// AutoApprove returns true if the given rpId has auto_approve set in config,
// allowing operations to proceed without user verification.
func (c *Config) AutoApprove(rpId string) bool {
	if c.Sites == nil {
		return false
	}
	site, ok := c.Sites[rpId]
	if !ok {
		return false
	}
	return site.AutoApprove
}
