package main

import (
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/barnettlynn/nfctools/pkg/ntag424"
	"github.com/barnettlynn/nfctools/reset/internal/config"
)

const configFileName = "config.yaml"

func main() {
	verbose := flag.Bool("v", false, "enable debug logging")
	logFormat := flag.String("log-format", "text", "log format: text or json")
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

	// Load config
	configPath, err := defaultConfigPath()
	if err != nil {
		log.Fatalf("resolve config path failed: %v", err)
	}
	fmt.Printf("Using config: %s\n", configPath)

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("config load failed: %v", err)
	}

	// Load keys
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

	// Load file three key (optional, defaults to zeros if not configured)
	var fileThreeKey []byte
	if cfg.Keys.FileThreeKeyFile != "" {
		fileThreeKey, err = ntag424.LoadKeyHexFile(cfg.Keys.FileThreeKeyFile)
		if err != nil {
			log.Fatalf("File three key file invalid: %v", err)
		}
	} else {
		fileThreeKey = make([]byte, 16) // zeros
	}

	fmt.Printf("AppMasterKey: %s\n", cfg.Keys.AppMasterKeyFile)
	fmt.Printf("SDM key: %s\n", cfg.Keys.SDMKeyFile)
	fmt.Printf("NDEF write key: %s\n", cfg.Keys.NDEFWriteKeyFile)
	if cfg.Keys.FileThreeKeyFile != "" {
		fmt.Printf("File three key: %s\n", cfg.Keys.FileThreeKeyFile)
	}

	// Connect to reader
	conn, err := ntag424.Connect(*cfg.Runtime.ReaderIndex)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	fmt.Printf("Using reader [%d]: %s\n", conn.ReaderIdx, conn.Reader)

	// Reset tag
	fmt.Println("Resetting tag to factory defaults...")
	if err := resetTag(conn, appMasterKey, sdmKey, ndefKey, fileThreeKey); err != nil {
		log.Fatalf("reset tag failed: %v", err)
	}

	fmt.Println("Tag successfully reset to factory defaults!")
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
