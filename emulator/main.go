package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"guide.apparel/ntag424"
)

func main() {
	var (
		uidHex     = flag.String("uid", "", "14-char hex string (7-byte tag UID, required)")
		counter    = flag.Uint("ctr", 0, "SDM read counter value")
		sdmKeyFile = flag.String("sdm-key-file", "../keys/SDMEncryptionKey.hex", "Path to SDM key .hex file")
		baseURL    = flag.String("url", "https://api.guideapparel.com/tap", "Base URL")
		verify     = flag.Bool("verify", false, "Self-verify the generated URL")
		verbose    = flag.Bool("v", false, "Enable debug logging")
		logFormat  = flag.String("log-format", "text", "Log format: text or json")
	)
	flag.Parse()

	// Setup logging
	var logger *slog.Logger
	if *logFormat == "json" {
		logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))
	} else {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))
	}
	if *verbose {
		if *logFormat == "json" {
			logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
				Level: slog.LevelDebug,
			}))
		} else {
			logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
				Level: slog.LevelDebug,
			}))
		}
	}
	slog.SetDefault(logger)

	// Validate required flags
	if *uidHex == "" {
		fmt.Fprintf(os.Stderr, "Error: -uid is required\n")
		flag.Usage()
		os.Exit(1)
	}

	if len(*uidHex) != 14 {
		fmt.Fprintf(os.Stderr, "Error: UID must be 14 hex characters (7 bytes), got %d\n", len(*uidHex))
		os.Exit(1)
	}

	if *counter > 0xFFFFFF {
		fmt.Fprintf(os.Stderr, "Error: counter must be <= 0xFFFFFF, got %d\n", *counter)
		os.Exit(1)
	}

	// Load SDM key
	slog.Debug("Loading SDM key", "path", *sdmKeyFile)
	sdmKey, err := ntag424.LoadKeyHexFile(*sdmKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading SDM key: %v\n", err)
		os.Exit(1)
	}
	slog.Debug("SDM key loaded", "key", fmt.Sprintf("%X", sdmKey))

	// Parse UID
	slog.Debug("Parsing UID", "uid", *uidHex)
	uid, err := hex.DecodeString(*uidHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding UID: %v\n", err)
		os.Exit(1)
	}
	if len(uid) != 7 {
		fmt.Fprintf(os.Stderr, "Error: UID must be 7 bytes, got %d\n", len(uid))
		os.Exit(1)
	}
	slog.Debug("UID parsed", "bytes", uid)

	// Generate SDM URL
	slog.Debug("Generating SDM URL", "baseURL", *baseURL, "counter", *counter)
	generatedURL, err := ntag424.GenerateSDMURL(*baseURL, uid, uint32(*counter), sdmKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating SDM URL: %v\n", err)
		os.Exit(1)
	}

	// Print output
	fmt.Printf("SDM key: %s\n", *sdmKeyFile)
	fmt.Printf("UID:     %s\n", *uidHex)
	fmt.Printf("Counter: %d\n", *counter)
	fmt.Printf("URL:     %s\n", generatedURL)

	// Verify if requested
	if *verify {
		slog.Debug("Verifying generated URL")
		match, err := ntag424.VerifySDMMAC(generatedURL, sdmKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error verifying URL: %v\n", err)
			os.Exit(1)
		}
		if match {
			fmt.Printf("Verify:  OK\n")
		} else {
			fmt.Printf("Verify:  FAILED\n")
			os.Exit(1)
		}
	}
}
