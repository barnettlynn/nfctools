package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Keys    KeysConfig    `yaml:"keys"`
	Runtime RuntimeConfig `yaml:"runtime"`
}

type KeysConfig struct {
	AppMasterKeyFile  string `yaml:"app_master_key_file"`
	SDMKeyFile        string `yaml:"sdm_key_file"`
	NDEFWriteKeyFile  string `yaml:"ndef_write_key_file"`
	FileThreeKeyFile  string `yaml:"file_three_key_file,omitempty"`
}

type RuntimeConfig struct {
	ReaderIndex *int `yaml:"reader_index"`
}

func Load(path string) (*Config, error) {
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
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) Validate() error {
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

	// FileThreeKeyFile is optional
	if strings.TrimSpace(c.Keys.FileThreeKeyFile) != "" {
		if err := validateReadableFile(c.Keys.FileThreeKeyFile, "config.keys.file_three_key_file"); err != nil {
			return err
		}
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
	c.Keys.FileThreeKeyFile = resolvePath(configDir, c.Keys.FileThreeKeyFile)
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
