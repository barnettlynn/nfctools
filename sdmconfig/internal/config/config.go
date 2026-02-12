package config

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type ValidationMode int

const (
	ValidationFull ValidationMode = iota
	ValidationAuthDiag
)

type Config struct {
	URL     string        `yaml:"url"`
	SDM     SDMConfig     `yaml:"sdm"`
	Auth    AuthConfig    `yaml:"auth"`
	Runtime RuntimeConfig `yaml:"runtime"`
}

type SDMConfig struct {
	FileNo   *int `yaml:"file_no"`
	SDMKeyNo *int `yaml:"sdm_key_no"`
}

type AuthConfig struct {
	SettingsKeyNo      *int   `yaml:"settings_key_no"`
	SettingsKeyHexFile string `yaml:"settings_key_hex_file"`
	File2WriteKeyNo    *int   `yaml:"file2_write_key_no"`
	File2WriteKeyFile  string `yaml:"file2_write_key_hex_file"`
}

type RuntimeConfig struct {
	ReaderIndex  *int  `yaml:"reader_index"`
	SettingsOnly *bool `yaml:"settings_only"`
	ForcePlain   *bool `yaml:"force_plain"`
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
	case ValidationAuthDiag:
		return c.validateAuthDiagMode()
	case ValidationFull:
		return c.validateFullMode()
	default:
		return fmt.Errorf("unsupported validation mode: %d", mode)
	}
}

func (c *Config) validateCommon() error {
	if c.Runtime.ReaderIndex == nil {
		return fmt.Errorf("config.runtime.reader_index is required")
	}
	if *c.Runtime.ReaderIndex < 0 {
		return fmt.Errorf("config.runtime.reader_index must be >= 0")
	}
	return nil
}

func (c *Config) validateAuthDiagMode() error {
	if c.Auth.SettingsKeyNo == nil {
		return fmt.Errorf("config.auth.settings_key_no is required")
	}
	if *c.Auth.SettingsKeyNo < 0 || *c.Auth.SettingsKeyNo > 15 {
		return fmt.Errorf("config.auth.settings_key_no must be 0..15")
	}
	if strings.TrimSpace(c.Auth.SettingsKeyHexFile) == "" {
		return fmt.Errorf("config.auth.settings_key_hex_file is required")
	}
	if err := validateReadableFile(c.Auth.SettingsKeyHexFile, "config.auth.settings_key_hex_file"); err != nil {
		return err
	}
	return nil
}

func (c *Config) validateFullMode() error {
	if strings.TrimSpace(c.URL) == "" {
		return fmt.Errorf("config.url is required")
	}
	parsedURL, err := url.Parse(c.URL)
	if err != nil {
		return fmt.Errorf("config.url is invalid: %w", err)
	}
	if parsedURL.Scheme == "" || parsedURL.Host == "" {
		return fmt.Errorf("config.url must be absolute (include scheme and host)")
	}

	if c.SDM.FileNo == nil {
		return fmt.Errorf("config.sdm.file_no is required")
	}
	if *c.SDM.FileNo < 0 || *c.SDM.FileNo > 0x1F {
		return fmt.Errorf("config.sdm.file_no must be 0..31")
	}
	if c.SDM.SDMKeyNo == nil {
		return fmt.Errorf("config.sdm.sdm_key_no is required")
	}
	if *c.SDM.SDMKeyNo < 0 || *c.SDM.SDMKeyNo > 15 {
		return fmt.Errorf("config.sdm.sdm_key_no must be 0..15")
	}

	if err := c.validateAuthDiagMode(); err != nil {
		return err
	}

	if c.Auth.File2WriteKeyNo == nil {
		return fmt.Errorf("config.auth.file2_write_key_no is required")
	}
	if *c.Auth.File2WriteKeyNo < 0 || *c.Auth.File2WriteKeyNo > 15 {
		return fmt.Errorf("config.auth.file2_write_key_no must be 0..15")
	}
	if strings.TrimSpace(c.Auth.File2WriteKeyFile) == "" {
		return fmt.Errorf("config.auth.file2_write_key_hex_file is required")
	}
	if err := validateReadableFile(c.Auth.File2WriteKeyFile, "config.auth.file2_write_key_hex_file"); err != nil {
		return err
	}

	if c.Runtime.SettingsOnly == nil {
		return fmt.Errorf("config.runtime.settings_only is required")
	}
	if c.Runtime.ForcePlain == nil {
		return fmt.Errorf("config.runtime.force_plain is required")
	}

	return nil
}

func (c *Config) resolvePaths(configPath string) {
	configDir := filepath.Dir(configPath)
	c.Auth.SettingsKeyHexFile = resolvePath(configDir, c.Auth.SettingsKeyHexFile)
	c.Auth.File2WriteKeyFile = resolvePath(configDir, c.Auth.File2WriteKeyFile)
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
