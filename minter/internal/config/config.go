package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type ValidationMode int

const (
	ValidationFull ValidationMode = iota
	ValidationEmulator
)

type Config struct {
	API     APIConfig     `yaml:"api"`
	Keys    KeysConfig    `yaml:"keys"`
	SDM     SDMConfig     `yaml:"sdm"`
	Runtime RuntimeConfig `yaml:"runtime"`
}

type APIConfig struct {
	Endpoint       string `yaml:"endpoint"`
	CFClientID     string `yaml:"cf_client_id"`
	CFClientSecret string `yaml:"cf_client_secret"`
}

type KeysConfig struct {
	AppMasterKeyFile string `yaml:"app_master_key_file"`
	SDMKeyFile       string `yaml:"sdm_key_file"`
	NDEFWriteKeyFile string `yaml:"ndef_write_key_file"`
}

type SDMConfig struct {
	BaseURL string `yaml:"base_url"`
}

type RuntimeConfig struct {
	ReaderIndex *int `yaml:"reader_index"`
}

func Load(path string) (*Config, error) {
	return LoadWithMode(path, ValidationFull)
}

func LoadWithMode(path string, mode ValidationMode) (*Config, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	dec := yaml.NewDecoder(bytes.NewReader(content))
	dec.KnownFields(true)

	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config yaml: %w", err)
	}
	cfg.resolvePaths(path)
	if err := cfg.ValidateWithMode(mode); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) Validate() error {
	return c.ValidateWithMode(ValidationFull)
}

func (c *Config) ValidateWithMode(mode ValidationMode) error {
	if err := c.validateCommon(); err != nil {
		return err
	}

	switch mode {
	case ValidationEmulator:
		return nil
	case ValidationFull:
		return c.validateFullMode()
	default:
		return fmt.Errorf("unsupported validation mode: %d", mode)
	}
}

func (c *Config) validateCommon() error {
	if strings.TrimSpace(c.API.Endpoint) == "" {
		return fmt.Errorf("config.api.endpoint is required")
	}
	if strings.TrimSpace(c.API.CFClientID) == "" {
		return fmt.Errorf("config.api.cf_client_id is required")
	}
	if strings.TrimSpace(c.API.CFClientSecret) == "" {
		return fmt.Errorf("config.api.cf_client_secret is required")
	}
	return nil
}

func (c *Config) validateFullMode() error {
	if strings.TrimSpace(c.Keys.AppMasterKeyFile) == "" {
		return fmt.Errorf("config.keys.app_master_key_file is required")
	}
	if err := validateReadableFile(c.Keys.AppMasterKeyFile, "config.keys.app_master_key_file"); err != nil {
		return err
	}

	if strings.TrimSpace(c.Keys.SDMKeyFile) == "" {
		return fmt.Errorf("config.keys.sdm_key_file is required")
	}
	if err := validateReadableFile(c.Keys.SDMKeyFile, "config.keys.sdm_key_file"); err != nil {
		return err
	}

	if strings.TrimSpace(c.Keys.NDEFWriteKeyFile) == "" {
		return fmt.Errorf("config.keys.ndef_write_key_file is required")
	}
	if err := validateReadableFile(c.Keys.NDEFWriteKeyFile, "config.keys.ndef_write_key_file"); err != nil {
		return err
	}

	if strings.TrimSpace(c.SDM.BaseURL) == "" {
		return fmt.Errorf("config.sdm.base_url is required")
	}

	if c.Runtime.ReaderIndex == nil {
		return fmt.Errorf("config.runtime.reader_index is required")
	}
	if *c.Runtime.ReaderIndex < 0 {
		return fmt.Errorf("config.runtime.reader_index must be >= 0")
	}

	return nil
}

func (c *Config) resolvePaths(configPath string) {
	configDir := filepath.Dir(configPath)
	c.Keys.AppMasterKeyFile = resolvePath(configDir, c.Keys.AppMasterKeyFile)
	c.Keys.SDMKeyFile = resolvePath(configDir, c.Keys.SDMKeyFile)
	c.Keys.NDEFWriteKeyFile = resolvePath(configDir, c.Keys.NDEFWriteKeyFile)
}

func resolvePath(baseDir, path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" || filepath.IsAbs(trimmed) {
		return trimmed
	}
	return filepath.Clean(filepath.Join(baseDir, trimmed))
}

func validateReadableFile(path string, field string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s must point to a file, got directory", field)
	}
	return nil
}
