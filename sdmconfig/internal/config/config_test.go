package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadValidFullConfigAndResolveRelativePaths(t *testing.T) {
	tmp := t.TempDir()
	settingsKeyPath := filepath.Join(tmp, "settings.hex")
	writeKeyPath := filepath.Join(tmp, "write.hex")
	if err := os.WriteFile(settingsKeyPath, []byte("00112233445566778899AABBCCDDEEFF\n"), 0o644); err != nil {
		t.Fatalf("write settings key: %v", err)
	}
	if err := os.WriteFile(writeKeyPath, []byte("FFEEDDCCBBAA99887766554433221100\n"), 0o644); err != nil {
		t.Fatalf("write write key: %v", err)
	}

	cfgPath := filepath.Join(tmp, "config.yaml")
	cfgYAML := `
url: "https://example.com/tap"
sdm:
  file_no: 2
  sdm_key_no: 1
auth:
  settings_key_no: 0
  settings_key_hex_file: "settings.hex"
  file2_write_key_no: 2
  file2_write_key_hex_file: "write.hex"
runtime:
  reader_index: 0
  settings_only: false
  force_plain: false
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.Auth.SettingsKeyHexFile != settingsKeyPath {
		t.Fatalf("expected resolved settings key path %q, got %q", settingsKeyPath, cfg.Auth.SettingsKeyHexFile)
	}
	if cfg.Auth.File2WriteKeyFile != writeKeyPath {
		t.Fatalf("expected resolved write key path %q, got %q", writeKeyPath, cfg.Auth.File2WriteKeyFile)
	}
}

func TestLoadWithModeAuthDiagAllowsMinimalConfig(t *testing.T) {
	tmp := t.TempDir()
	settingsKeyPath := filepath.Join(tmp, "settings.hex")
	if err := os.WriteFile(settingsKeyPath, []byte("00112233445566778899AABBCCDDEEFF\n"), 0o644); err != nil {
		t.Fatalf("write settings key: %v", err)
	}

	cfgPath := filepath.Join(tmp, "config.yaml")
	cfgYAML := `
auth:
  settings_key_no: 0
  settings_key_hex_file: "settings.hex"
runtime:
  reader_index: 0
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadWithMode(cfgPath, ValidationAuthDiag)
	if err != nil {
		t.Fatalf("LoadWithMode returned error: %v", err)
	}
	if cfg.Auth.SettingsKeyHexFile != settingsKeyPath {
		t.Fatalf("expected resolved settings key path %q, got %q", settingsKeyPath, cfg.Auth.SettingsKeyHexFile)
	}
}

func TestLoadWithModeAuthDiagFailsWithoutSettingsKey(t *testing.T) {
	cfgPath := writeConfig(t, `
auth:
  settings_key_no: 0
runtime:
  reader_index: 0
`)

	_, err := LoadWithMode(cfgPath, ValidationAuthDiag)
	if err == nil || !strings.Contains(err.Error(), "config.auth.settings_key_hex_file is required") {
		t.Fatalf("expected missing settings key file error, got %v", err)
	}
}

func TestLoadFullFailsOnInvalidURL(t *testing.T) {
	cfgPath := writeConfigWithKeys(t, `
url: "example.com/tap"
sdm:
  file_no: 2
  sdm_key_no: 1
auth:
  settings_key_no: 0
  settings_key_hex_file: "SETTINGS"
  file2_write_key_no: 2
  file2_write_key_hex_file: "WRITE"
runtime:
  reader_index: 0
  settings_only: false
  force_plain: false
`, "SETTINGS", "WRITE")

	_, err := Load(cfgPath)
	if err == nil || !strings.Contains(err.Error(), "must be absolute") {
		t.Fatalf("expected absolute URL error, got %v", err)
	}
}

func TestLoadFullFailsWhenWriteAuthMissing(t *testing.T) {
	cfgPath := writeConfigWithKeys(t, `
url: "https://example.com/tap"
sdm:
  file_no: 2
  sdm_key_no: 1
auth:
  settings_key_no: 0
  settings_key_hex_file: "SETTINGS"
runtime:
  reader_index: 0
  settings_only: false
  force_plain: false
`, "SETTINGS", "WRITE")

	_, err := Load(cfgPath)
	if err == nil || !strings.Contains(err.Error(), "config.auth.file2_write_key_no is required") {
		t.Fatalf("expected missing file2 write key slot error, got %v", err)
	}
}

func TestLoadFullFailsWhenRuntimeBoolMissing(t *testing.T) {
	cfgPath := writeConfigWithKeys(t, `
url: "https://example.com/tap"
sdm:
  file_no: 2
  sdm_key_no: 1
auth:
  settings_key_no: 0
  settings_key_hex_file: "SETTINGS"
  file2_write_key_no: 2
  file2_write_key_hex_file: "WRITE"
runtime:
  reader_index: 0
  force_plain: false
`, "SETTINGS", "WRITE")

	_, err := Load(cfgPath)
	if err == nil || !strings.Contains(err.Error(), "config.runtime.settings_only is required") {
		t.Fatalf("expected missing settings_only error, got %v", err)
	}
}

func TestLoadFullFailsWhenSettingsKeyMissing(t *testing.T) {
	cfgPath := writeConfig(t, `
url: "https://example.com/tap"
sdm:
  file_no: 2
  sdm_key_no: 1
auth:
  settings_key_no: 0
  settings_key_hex_file: "missing-settings.hex"
  file2_write_key_no: 2
  file2_write_key_hex_file: "missing-write.hex"
runtime:
  reader_index: 0
  settings_only: false
  force_plain: false
`)

	_, err := Load(cfgPath)
	if err == nil || !strings.Contains(err.Error(), "config.auth.settings_key_hex_file") {
		t.Fatalf("expected missing settings key file error, got %v", err)
	}
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return cfgPath
}

func writeConfigWithKeys(t *testing.T, content, settingsName, writeName string) string {
	t.Helper()
	cfgPath := writeConfig(t, content)
	baseDir := filepath.Dir(cfgPath)
	settingsPath := filepath.Join(baseDir, settingsName)
	writePath := filepath.Join(baseDir, writeName)
	if err := os.WriteFile(settingsPath, []byte("00112233445566778899AABBCCDDEEFF\n"), 0o644); err != nil {
		t.Fatalf("write settings key: %v", err)
	}
	if err := os.WriteFile(writePath, []byte("00112233445566778899AABBCCDDEEFF\n"), 0o644); err != nil {
		t.Fatalf("write write key: %v", err)
	}
	return cfgPath
}
