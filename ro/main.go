package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ebfe/scard"
)

func readAndPrint(ctx *scard.Context, reader string, cfg *readerConfig) {
	card, err := ctx.Connect(reader, scard.ShareShared, scard.ProtocolAny)
	if err != nil {
		log.Printf("Connect failed: %v", err)
		return
	}
	defer card.Disconnect(scard.LeaveCard)

	uid, err := getUID(card)
	if err != nil {
		log.Printf("UID error: %v", err)
	} else {
		fmt.Printf("UID: %s\n", hexUpper(uid))
	}

	// Get tag version info (PICC-level command, no auth needed)
	version, err := getVersion(card)
	if err != nil {
		log.Printf("Version error: %v", err)
	} else {
		printTagVersion(version)
	}

	// List applications and files
	apps, err := getApplicationIDs(card)
	if err != nil {
		// NTAG 424 DNA doesn't support GetApplicationIDs command - skip silently
		fmt.Println("Applications: (not available on this tag)")
	} else {
		printApplications(card, apps)
	}

	// Show key slot information
	printKeySlots(card, cfg)

	// Show detailed file settings and access rights
	printFilesInfo(card, cfg)

	// Read and display NDEF (moved here after file settings)
	ndef, err := readNDEF(card)
	if err != nil {
		log.Printf("NDEF error: %v", err)
	} else if len(ndef) == 0 {
		fmt.Println("NDEF: (empty)")
	} else {
		fmt.Printf("NDEF: %s\n", hexUpper(ndef))
		printNDEFInfo(ndef)
		if url, err := decodeNDEFURI(ndef); err == nil {
			fmt.Printf("URL: %s\n", url)
			printSDMVerify(url, cfg.sdmKey, cfg.sdmKeyLabel, cfg.sdmKeyNo)
		}
	}

	// Read and display File 1 (CC)
	ccData, err := readCCFile(card)
	if err != nil {
		log.Printf("CC file error: %v", err)
	} else {
		printCCFile(ccData)
	}

	// Read and display File 3 (proprietary)
	f3Data, f3Settings, err := readFile3(card, cfg)
	if err != nil {
		log.Printf("File 3 error: %v", err)
	} else {
		printFile3(f3Data, f3Settings, cfg)
	}
}

func main() {
	verbose := flag.Bool("v", false, "enable debug logging")
	logFormat := flag.String("log-format", "text", "log format: text or json")
	authKeyFile := flag.String("auth-key-file", filepath.Join("..", "keys", "AppMasterKey.hex"), "path to AppMasterKey file (KeyNo 0)")
	authKeyHex := flag.String("auth-key", "", "optional 32-hex auth key")
	authKeyNo := flag.Int("auth-keyno", 0, "auth key number (default: 0)")
	sdmKeyFile := flag.String("sdm-key-file", filepath.Join("..", "keys", "SDMEncryptionKey.hex"), "path to SDM key file (KeyNo 1)")
	sdmKeyHex := flag.String("sdm-key", "", "optional 32-hex SDM key")
	sdmKeyNo := flag.Int("sdm-keyno", 1, "SDM key number (default: 1)")
	fileNo := flag.Int("file", 2, "file number for SDM settings (default: 2)")
	fullProbe := flag.Bool("full-probe", false, "probe all 16 key slots (default: probe only expected slots)")
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

	if *authKeyNo < 0 || *authKeyNo > 15 {
		log.Fatalf("-auth-keyno must be 0..15")
	}
	if *sdmKeyNo < 0 || *sdmKeyNo > 15 {
		log.Fatalf("-sdm-keyno must be 0..15")
	}
	if *fileNo < 0 || *fileNo > 0x1F {
		log.Fatalf("-file must be 0..31")
	}

	var authKey []byte
	authKeyLabel := ""
	if *authKeyHex != "" {
		if len(*authKeyHex) != 32 {
			log.Fatalf("-auth-key must be 32 hex chars")
		}
		b, err := hex.DecodeString(*authKeyHex)
		if err != nil {
			log.Fatalf("-auth-key invalid hex: %v", err)
		}
		authKey = b
		authKeyLabel = "(inline)"
	} else {
		key, err := loadKeyHexFile(*authKeyFile)
		if err != nil {
			log.Fatalf("-auth-key-file error: %v", err)
		}
		authKey = key
		authKeyLabel = *authKeyFile
	}

	var sdmKey []byte
	sdmKeyLabel := ""
	if *sdmKeyHex != "" {
		if len(*sdmKeyHex) != 32 {
			log.Fatalf("-sdm-key must be 32 hex chars")
		}
		b, err := hex.DecodeString(*sdmKeyHex)
		if err != nil {
			log.Fatalf("-sdm-key invalid hex: %v", err)
		}
		sdmKey = b
		sdmKeyLabel = "(inline)"
	} else {
		key, err := loadKeyHexFile(*sdmKeyFile)
		if err != nil {
			defaultPath := filepath.Join("..", "keys", "SDMEncryptionKey.hex")
			if *sdmKeyFile == defaultPath {
				fallback, ferr := findDefaultKeyFile()
				if ferr != nil {
					log.Fatalf("-sdm-key-file error: %v", err)
				}
				key, err = loadKeyHexFile(fallback)
				if err != nil {
					log.Fatalf("fallback key file error: %v", err)
				}
				sdmKey = key
				sdmKeyLabel = fallback
			} else {
				log.Fatalf("-sdm-key-file error: %v", err)
			}
		} else {
			sdmKey = key
			sdmKeyLabel = *sdmKeyFile
		}
	}

	ndefKeyPath := filepath.Join("..", "keys", "FileTwoWrite.hex")
	ndefKeyLabel := ndefKeyPath
	if _, err := os.Stat(ndefKeyPath); err != nil {
		ndefKeyLabel = fmt.Sprintf("%s (missing)", ndefKeyPath)
	}

	cfg := &readerConfig{
		authKey:      authKey,
		authKeyNo:    byte(*authKeyNo),
		authKeyLabel: authKeyLabel,
		sdmKey:       sdmKey,
		sdmKeyLabel:  sdmKeyLabel,
		sdmKeyNo:     byte(*sdmKeyNo),
		ndefKeyLabel: ndefKeyLabel,
		ndefKeyNo:    0x02,
		fileNo:       byte(*fileNo),
		fullProbe:    *fullProbe,
	}

	ctx, err := scard.EstablishContext()
	if err != nil {
		log.Fatalf("EstablishContext failed: %v", err)
	}
	defer ctx.Release()

	// Set up signal handling for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		fmt.Printf("\nReceived %v, shutting down...\n", sig)
		ctx.Release()
		os.Exit(0)
	}()

	readers, err := ctx.ListReaders()
	if err != nil || len(readers) == 0 {
		log.Fatalf("No readers found: %v", err)
	}

	readerIndex := 0
	reader := readers[0]
	args := flag.Args()
	if len(args) > 0 {
		arg := args[0]
		if v, err := strconv.Atoi(arg); err == nil {
			if v >= 0 && v < len(readers) {
				readerIndex = v
				reader = readers[readerIndex]
			} else {
				log.Printf("Reader index out of range (0..%d), using 0", len(readers)-1)
			}
		} else {
			// Treat as a substring match on the reader name.
			found := false
			for i, r := range readers {
				if strings.Contains(r, arg) {
					readerIndex = i
					reader = r
					found = true
					break
				}
			}
			if !found {
				log.Printf("Reader name not found (%s), using 0", arg)
			}
		}
	}
	fmt.Printf("Using reader [%d]: %s\n", readerIndex, reader)

	states := []scard.ReaderState{{
		Reader:       reader,
		CurrentState: scard.StateUnaware,
	}}
	cardPresent := false

	fmt.Println("Waiting for card scans...")
	for {
		if err := ctx.GetStatusChange(states, time.Second); err != nil {
			if err == scard.ErrTimeout {
				continue
			}
			log.Printf("GetStatusChange error: %v", err)
			continue
		}

		rs := states[0]
		if (rs.EventState&scard.StatePresent) != 0 && !cardPresent {
			cardPresent = true
			readAndPrint(ctx, reader, cfg)
			fmt.Println("Waiting for next scan...")
		} else if (rs.EventState&scard.StateEmpty) != 0 && cardPresent {
			cardPresent = false
		}

		states[0].CurrentState = rs.EventState
	}
}

