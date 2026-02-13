package main

import (
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/barnettlynn/nfctools/minter/internal/config"
	"github.com/barnettlynn/nfctools/pkg/ntag424"
)

const configFileName = "config.yaml"

func main() {
	verbose := flag.Bool("v", false, "enable debug logging")
	logFormat := flag.String("log-format", "text", "log format: text or json")
	emulator := flag.Bool("emulator", false, "skip physical card and use provided UID (for API testing)")
	uid := flag.String("uid", "", "tag UID hex (required in emulator mode, optional override in physical mode)")
	hatName := flag.String("hat-name", "", "hat name (required)")
	hatColor := flag.String("hat-color", "", "hat color (required)")
	hatSKU := flag.String("hat-sku", "", "hat SKU (optional)")
	batchID := flag.String("batch-id", "", "batch ID (optional)")
	scanCount := flag.Int("scan-count", 0, "scan count (optional)")
	notes := flag.String("notes", "", "notes (optional)")
	flag.Parse()

	// Configure slog
	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	opts := &slog.HandlerOptions{Level: level}
	if *logFormat == "json" {
		slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, opts)))
	} else {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, opts)))
	}

	// Validate required flags
	if strings.TrimSpace(*hatName) == "" {
		log.Fatalf("-hat-name is required")
	}
	if strings.TrimSpace(*hatColor) == "" {
		log.Fatalf("-hat-color is required")
	}
	if *emulator && strings.TrimSpace(*uid) == "" {
		log.Fatalf("-uid is required in emulator mode")
	}

	// Load config
	configPath, err := defaultConfigPath()
	if err != nil {
		log.Fatalf("resolve config path failed: %v", err)
	}
	fmt.Printf("Using config: %s\n", configPath)

	var cfg *config.Config
	if *emulator {
		cfg, err = config.LoadWithMode(configPath, config.ValidationEmulator)
	} else {
		cfg, err = config.LoadWithMode(configPath, config.ValidationFull)
	}
	if err != nil {
		log.Fatalf("config load failed: %v", err)
	}

	var tagUID string

	if *emulator {
		// Emulator mode: use provided UID, skip provisioning
		tagUID = strings.ToLower(strings.TrimSpace(*uid))
		fmt.Printf("Emulator mode: using provided UID: %s\n", tagUID)
	} else {
		// Physical mode: load keys and provision tag
		appMasterKey, err := ntag424.LoadKeyHexFile(cfg.Keys.AppMasterKeyFile)
		if err != nil {
			log.Fatalf("app master key file invalid: %v", err)
		}
		sdmKey, err := ntag424.LoadKeyHexFile(cfg.Keys.SDMKeyFile)
		if err != nil {
			log.Fatalf("SDM key file invalid: %v", err)
		}
		ndefKey, err := ntag424.LoadKeyHexFile(cfg.Keys.NDEFWriteKeyFile)
		if err != nil {
			log.Fatalf("NDEF write key file invalid: %v", err)
		}

		fmt.Printf("AppMasterKey: %s\n", cfg.Keys.AppMasterKeyFile)
		fmt.Printf("SDM key: %s\n", cfg.Keys.SDMKeyFile)
		fmt.Printf("NDEF write key: %s\n", cfg.Keys.NDEFWriteKeyFile)
		fmt.Printf("SDM base URL: %s\n", cfg.SDM.BaseURL)

		conn, err := ntag424.Connect(*cfg.Runtime.ReaderIndex)
		if err != nil {
			log.Fatal(err)
		}
		defer conn.Close()
		fmt.Printf("Using reader [%d]: %s\n", conn.ReaderIdx, conn.Reader)

		fmt.Println("Provisioning tag...")
		provisionedUID, err := provisionTag(conn, appMasterKey, sdmKey, ndefKey, cfg.SDM.BaseURL)
		if err != nil {
			log.Fatalf("provision tag failed: %v", err)
		}

		// Use override UID if provided, otherwise use provisioned UID (lowercased for API)
		if strings.TrimSpace(*uid) != "" {
			tagUID = strings.ToLower(strings.TrimSpace(*uid))
			fmt.Printf("Using override UID: %s (provisioned UID: %s)\n", tagUID, provisionedUID)
		} else {
			tagUID = strings.ToLower(provisionedUID)
			fmt.Printf("Provisioned UID: %s\n", tagUID)
		}
	}

	// Build registration payload
	reg := TagRegistration{
		UID:       tagUID,
		HatName:   strings.TrimSpace(*hatName),
		HatColor:  strings.TrimSpace(*hatColor),
		HatSKU:    strings.TrimSpace(*hatSKU),
		BatchID:   strings.TrimSpace(*batchID),
		ScanCount: *scanCount,
		Notes:     strings.TrimSpace(*notes),
	}

	// Register tag with API
	fmt.Printf("Registering tag with API: %s\n", cfg.API.Endpoint)
	if err := registerTag(cfg.API.Endpoint, cfg.API.BearerToken, reg); err != nil {
		log.Fatalf("register tag failed: %v", err)
	}

	fmt.Println("Tag registered successfully!")
	fmt.Printf("  UID: %s\n", tagUID)
	fmt.Printf("  Hat: %s - %s\n", reg.HatName, reg.HatColor)
	if reg.HatSKU != "" {
		fmt.Printf("  SKU: %s\n", reg.HatSKU)
	}
	if reg.BatchID != "" {
		fmt.Printf("  Batch: %s\n", reg.BatchID)
	}
}

func defaultConfigPath() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}
	exeConfigPath := filepath.Join(filepath.Dir(exePath), configFileName)
	if fileExists(exeConfigPath) {
		return exeConfigPath, nil
	}

	// Fallback for `go run`, where the executable is placed in a temp directory.
	cwd, err := os.Getwd()
	if err != nil {
		return exeConfigPath, nil
	}
	cwdConfigPath := filepath.Join(cwd, configFileName)
	if fileExists(cwdConfigPath) {
		return cwdConfigPath, nil
	}
	return exeConfigPath, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
