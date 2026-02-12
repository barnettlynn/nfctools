package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"

	"github.com/ebfe/scard"
)

const (
	defaultBaseURL   = "https://api.guideapparel.com/tap"
	counterFileNo    = 0x02
	authDefaultKeyNo = 0x00
)

func main() {
	verbose := flag.Bool("v", false, "enable debug logging")
	logFormat := flag.String("log-format", "text", "log format: text or json")
	appMasterKeyFile := flag.String("app-master-key-file", "../keys/AppMasterKey.hex", "path to AppMasterKey file (KeyNo 0)")
	sdmKeyFile := flag.String("sdm-key-file", "../keys/SDMEncryptionKey.hex", "path to SDM key file (KeyNo 1)")
	ndefKeyFile := flag.String("ndef-key-file", "../keys/FileTwoWrite.hex", "path to File Two Write key file (KeyNo 2)")
	baseURL := flag.String("url", defaultBaseURL, "base URL for SDM NDEF")
	readerIndex := flag.Int("reader", 0, "reader index")
	authKeyHex := flag.String("auth-key", "", "optional 32-hex auth key (default: all zeroes)")
	authKeyNo := flag.Int("auth-keyno", authDefaultKeyNo, "auth key number (default: 0)")
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

	appMasterKey, err := loadKeyHexFile(*appMasterKeyFile)
	if err != nil {
		log.Fatalf("AppMasterKey file error: %v", err)
	}
	sdmKey, err := loadKeyHexFile(*sdmKeyFile)
	if err != nil {
		log.Fatalf("SDM key file error: %v", err)
	}
	ndefKey, err := loadKeyHexFile(*ndefKeyFile)
	if err != nil {
		log.Fatalf("NDEF key file error: %v", err)
	}

	authKey := make([]byte, 16)
	if *authKeyHex != "" {
		if len(*authKeyHex) != 32 {
			log.Fatalf("-auth-key must be 32 hex chars")
		}
		b, err := hex.DecodeString(*authKeyHex)
		if err != nil {
			log.Fatalf("-auth-key invalid hex: %v", err)
		}
		copy(authKey, b)
	}

	ctx, err := scard.EstablishContext()
	if err != nil {
		log.Fatalf("EstablishContext failed: %v", err)
	}
	defer ctx.Release()

	readers, err := ctx.ListReaders()
	if err != nil || len(readers) == 0 {
		log.Fatalf("No readers found: %v", err)
	}
	if *readerIndex < 0 || *readerIndex >= len(readers) {
		log.Fatalf("Reader index out of range (0..%d)", len(readers)-1)
	}
	reader := readers[*readerIndex]
	fmt.Printf("Using reader [%d]: %s\n", *readerIndex, reader)

	card, err := ctx.Connect(reader, scard.ShareShared, scard.ProtocolAny)
	if err != nil {
		log.Fatalf("Connect failed: %v", err)
	}
	defer card.Disconnect(scard.LeaveCard)

	fmt.Printf("AppMasterKey (KeyNo 0): %s\n", *appMasterKeyFile)
	fmt.Printf("SDM key (KeyNo 1): %s\n", *sdmKeyFile)
	fmt.Printf("NDEF key (KeyNo 2): %s\n", *ndefKeyFile)
	fmt.Printf("SDM base URL: %s\n", *baseURL)

	// 1) Authenticate with auth key (default zero key 0x00)
	sess, err := authenticateEV2First(card, authKey, byte(*authKeyNo))
	if err != nil {
		log.Fatalf("Auth EV2First failed: %v", err)
	}

	// 2) ChangeKey for KeyNo 1 (SDM) and KeyNo 2 (File Two Write), old keys assumed zero
	zeroKey := make([]byte, 16)
	if err := changeKey(card, sess, 0x01, zeroKey, sdmKey, 0x01); err != nil {
		log.Fatalf("ChangeKey (KeyNo 1) failed: %v", err)
	}
	if err := changeKey(card, sess, 0x02, zeroKey, ndefKey, 0x01); err != nil {
		log.Fatalf("ChangeKey (KeyNo 2) failed: %v", err)
	}
	// 3) ChangeKey for KeyNo 0 (CAR/config) using current auth key as old key
	if err := changeKey(card, sess, 0x00, authKey, appMasterKey, 0x01); err != nil {
		log.Fatalf("ChangeKey (KeyNo 0) failed: %v", err)
	}
	fmt.Println("ChangeKey OK (KeyNo 0/1/2)")

	// 4) Build SDM NDEF template
	sdm, err := buildSDMNDEF(*baseURL)
	if err != nil {
		log.Fatalf("Build SDM NDEF failed: %v", err)
	}
	fmt.Printf("SDM URL template: %s\n", sdm.url)

	// 5) Re-authenticate with new CAR key before SDM settings
	sess, err = authenticateEV2First(card, appMasterKey, 0x00)
	if err != nil {
		log.Fatalf("Auth EV2First (CAR key) failed: %v", err)
	}

	// 6) Lock File Two Write access to KeyNo 2, keep read free, CAR on KeyNo 0
	const (
		rwKeyNo  = 0x02
		carKeyNo = 0x00
		rKeyNo   = 0x0E
		wKeyNo   = 0x02
	)
	ar1 := byte((rwKeyNo << 4) | carKeyNo)
	ar2 := byte((rKeyNo << 4) | wKeyNo)
	fmt.Printf("AccessRights set to: %02X %02X (RW=%X CAR=%X R=%X W=%X)\n",
		ar1, ar2, rwKeyNo, carKeyNo, rKeyNo, wKeyNo)

	// 7) ChangeFileSettings for SDM
	sdmOptions := byte(0xC1) // UID+ReadCtr mirroring, ASCII
	sdmMeta := byte(0x0E)    // plain meta
	sdmFile := byte(0x01)
	sdmCtr := byte(0x01)
	if err := changeFileSettingsSDM(card, sess, counterFileNo, 0x00, ar1, ar2,
		sdmOptions, sdmMeta, sdmFile, sdmCtr,
		sdm.uidOffset, sdm.ctrOffset, sdm.macInputOffset, sdm.macOffset); err != nil {
		log.Fatalf("ChangeFileSettings failed: %v", err)
	}
	fmt.Println("ChangeFileSettings OK")

	// 8) Write NDEF template (plain)
	if err := writeNDEFPlain(card, sdm.ndef); err != nil {
		log.Fatalf("Write NDEF failed: %v", err)
	}
	fmt.Println("NDEF template written")
	fmt.Println("Done")
}

