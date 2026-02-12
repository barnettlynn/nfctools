package main

import (
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/barnettlynn/nfctools/pkg/ntag424"
	"github.com/barnettlynn/nfctools/sdmconfig/internal/config"
)

const configFileName = "config.yaml"

func main() {
	verbose := flag.Bool("v", false, "enable debug logging")
	logFormat := flag.String("log-format", "text", "log format: text or json")
	diagAuth := flag.Bool("diag-auth", false, "diagnose EV2 authentication across key slots and exit")
	disableSDM := flag.Bool("disable-sdm", false, "disable SDM on the tag and exit")
	enableSDM := flag.Bool("enable-sdm", false, "enable SDM on the tag (assumes SDM is currently disabled)")
	updateSDM := flag.Bool("update-sdm", false, "update NDEF when SDM is enabled (disable -> write -> re-enable)")
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

	configPath, err := defaultConfigPath()
	if err != nil {
		log.Fatalf("resolve config path failed: %v", err)
	}
	fmt.Printf("Using config: %s\n", configPath)

	if *diagAuth {
		runAuthDiagnostics(configPath)
		return
	}

	if *disableSDM {
		runDisableSDM(configPath)
		return
	}

	if *enableSDM {
		runEnableSDM(configPath)
		return
	}

	if *updateSDM {
		runUpdateSDM(configPath)
		return
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("config load failed: %v", err)
	}

	settingsKey, err := ntag424.LoadKeyHexFile(cfg.Auth.SettingsKeyHexFile)
	if err != nil {
		log.Fatalf("settings key file invalid: %v", err)
	}
	file2WriteKey, err := ntag424.LoadKeyHexFile(cfg.Auth.File2WriteKeyFile)
	if err != nil {
		log.Fatalf("file2 write key file invalid: %v", err)
	}

	sdm, err := ntag424.BuildSDMNDEF(cfg.URL)
	if err != nil {
		log.Fatalf("Build SDM NDEF failed: %v", err)
	}
	fmt.Printf("New SDM URL template: %s\n", sdm.URL)

	conn, err := ntag424.Connect(*cfg.Runtime.ReaderIndex)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	fmt.Printf("Using reader [%d]: %s\n", conn.ReaderIdx, conn.Reader)

	if err := ntag424.SelectNDEFApp(conn.Card); err != nil {
		log.Fatalf("SELECT NDEF app failed before auth/context setup: %v", err)
	}

	settingsSess, err := ntag424.AuthenticateEV2First(conn.Card, settingsKey, byte(*cfg.Auth.SettingsKeyNo))
	if err != nil {
		log.Fatalf("Settings auth EV2First failed: %v", err)
	}

	fileNo := byte(*cfg.SDM.FileNo)
	sdmKeyNo := byte(*cfg.SDM.SDMKeyNo)

	// Get current settings to preserve AR values
	targetAR1 := byte(0x20) // Standard: RW=slot 2, Change=slot 0
	targetAR2 := byte(0xE2) // Standard: Read=free, Write=slot 2
	currentFS, err := ntag424.GetFileSettings(conn.Card, settingsSess, fileNo)
	if err != nil {
		slog.Debug("GetFileSettings failed, using standard AR", "error", err)
	} else {
		targetAR1 = currentFS.AR1
		targetAR2 = currentFS.AR2
		fmt.Println()
		ntag424.PrintFileSettings("CURRENT", fileNo, currentFS)
		fmt.Println()
	}

	// Re-auth before ChangeFileSettings to ensure fresh session
	settingsSess, err = ntag424.AuthenticateEV2First(conn.Card, settingsKey, byte(*cfg.Auth.SettingsKeyNo))
	if err != nil {
		log.Fatalf("Re-auth before ChangeFileSettings failed: %v", err)
	}

	fs := &ntag424.FileSettings{
		FileOption: 0x40,
		AR1:        targetAR1,
		AR2:        targetAR2,
		SDMOptions: 0xC1,
		SDMMeta:    0x0E,
		SDMFile:    sdmKeyNo,
		SDMCtr:     sdmKeyNo,
	}

	ntag424.PrintFileSettings("TARGET", fileNo, fs)
	fmt.Println()

	fmt.Printf("  SDM Offsets (for debugging):\n")
	fmt.Printf("    UIDOffset:      %d (0x%06X)\n", sdm.UIDOffset, sdm.UIDOffset)
	fmt.Printf("    CtrOffset:      %d (0x%06X)\n", sdm.CtrOffset, sdm.CtrOffset)
	fmt.Printf("    MacInputOffset: %d (0x%06X)\n", sdm.MacInputOffset, sdm.MacInputOffset)
	fmt.Printf("    MacOffset:      %d (0x%06X)\n", sdm.MacOffset, sdm.MacOffset)
	fmt.Println()

	if !*cfg.Runtime.ForcePlain {
		if err := ntag424.ChangeFileSettingsSDM(conn.Card, settingsSess, fileNo, 0x00, fs.AR1, fs.AR2,
			fs.SDMOptions, fs.SDMMeta, fs.SDMFile, fs.SDMCtr,
			sdm.UIDOffset, sdm.CtrOffset, sdm.MacInputOffset, sdm.MacOffset); err != nil {
			log.Fatalf("ChangeFileSettings failed: %v", err)
		}
		fmt.Println("ChangeFileSettings OK")
	} else {
		fmt.Println("Skipping ChangeFileSettings (force-plain)")
	}

	if !*cfg.Runtime.SettingsOnly {
		if _, err := ntag424.AuthenticateEV2First(conn.Card, file2WriteKey, byte(*cfg.Auth.File2WriteKeyNo)); err != nil {
			log.Fatalf("File 2 write auth EV2First failed: %v", err)
		}
		// Use WriteNDEFWithAuth instead of WriteNDEFPlain to preserve auth session
		// (WriteNDEFPlain would re-select the app and lose authentication)
		if err := ntag424.WriteNDEFWithAuth(conn.Card, sdm.NDEF); err != nil {
			log.Fatalf("Write NDEF failed: %v", err)
		}
		fmt.Println("NDEF template written")
	} else {
		fmt.Println("Skipping File Two Write (settings-only mode)")
	}

	// Read final settings to confirm changes
	finalSess := settingsSess
	if !*cfg.Runtime.SettingsOnly {
		reAuthSess, err := ntag424.AuthenticateEV2First(conn.Card, settingsKey, byte(*cfg.Auth.SettingsKeyNo))
		if err != nil {
			fmt.Printf("\nWarning: could not re-auth for final settings read: %v\n", err)
		} else {
			finalSess = reAuthSess
		}
	}

	finalFS, err := ntag424.GetFileSettings(conn.Card, finalSess, fileNo)
	if err != nil {
		fmt.Printf("\nError: could not read final file settings: %v\n", err)
	} else {
		fmt.Println()
		ntag424.PrintFileSettings("FINAL", fileNo, finalFS)
	}

	fmt.Println("\nDone")
}

func runDisableSDM(configPath string) {
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("config load failed: %v", err)
	}

	settingsKey, err := ntag424.LoadKeyHexFile(cfg.Auth.SettingsKeyHexFile)
	if err != nil {
		log.Fatalf("settings key file invalid: %v", err)
	}

	conn, err := ntag424.Connect(*cfg.Runtime.ReaderIndex)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	fmt.Printf("Using reader [%d]: %s\n", conn.ReaderIdx, conn.Reader)

	if err := ntag424.SelectNDEFApp(conn.Card); err != nil {
		log.Fatalf("SELECT NDEF app failed: %v", err)
	}

	settingsSess, err := ntag424.AuthenticateEV2First(conn.Card, settingsKey, byte(*cfg.Auth.SettingsKeyNo))
	if err != nil {
		log.Fatalf("Settings auth EV2First failed: %v", err)
	}

	fileNo := byte(*cfg.SDM.FileNo)

	// Get current file settings (optional - for display purposes)
	currentFS, err := ntag424.GetFileSettings(conn.Card, settingsSess, fileNo)
	if err != nil {
		slog.Debug("GetFileSettings failed, workflow continues", "error", err)
	} else {
		fmt.Println()
		ntag424.PrintFileSettings("CURRENT", fileNo, currentFS)
		fmt.Println()
	}

	// Re-auth before ChangeFileSettings to ensure fresh session
	settingsSess, err = ntag424.AuthenticateEV2First(conn.Card, settingsKey, byte(*cfg.Auth.SettingsKeyNo))
	if err != nil {
		log.Fatalf("Re-auth before ChangeFileSettings failed: %v", err)
	}

	// Disable SDM: Set explicit AR values for disabled state (free read/write)
	fs := &ntag424.FileSettings{
		FileOption: 0x00, // Plain communication, SDM disabled
		AR1:        0xE0, // Free read, slot 0 for change settings
		AR2:        0xEE, // Free write (E=free for write, E=free for RW)
		SDMOptions: 0x00,
		SDMMeta:    0x0F,
		SDMFile:    0x0F,
		SDMCtr:     0x0F,
	}

	ntag424.PrintFileSettings("TARGET", fileNo, fs)
	fmt.Println()

	// Use basic 3-byte format to disable SDM
	if err := ntag424.ChangeFileSettingsBasic(conn.Card, settingsSess, fileNo, fs.FileOption, fs.AR1, fs.AR2); err != nil {
		log.Fatalf("ChangeFileSettings failed: %v", err)
	}
	fmt.Println("SDM disabled successfully")

	// Re-select NDEF app to refresh file context
	if err := ntag424.SelectNDEFApp(conn.Card); err != nil {
		fmt.Printf("\nWarning: could not re-select NDEF app: %v\n", err)
	}

	// Read final settings to confirm changes
	finalSess, err := ntag424.AuthenticateEV2First(conn.Card, settingsKey, byte(*cfg.Auth.SettingsKeyNo))
	if err != nil {
		fmt.Printf("\nWarning: could not re-auth for final settings read: %v\n", err)
	} else {
		finalFS, err := ntag424.GetFileSettings(conn.Card, finalSess, fileNo)
		if err != nil {
			fmt.Printf("\nError: could not read final file settings: %v\n", err)
		} else {
			fmt.Println()
			ntag424.PrintFileSettings("FINAL", fileNo, finalFS)
		}
	}

	fmt.Println("\nDone")
}

func runEnableSDM(configPath string) {
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("config load failed: %v", err)
	}

	settingsKey, err := ntag424.LoadKeyHexFile(cfg.Auth.SettingsKeyHexFile)
	if err != nil {
		log.Fatalf("settings key file invalid: %v", err)
	}

	sdm, err := ntag424.BuildSDMNDEF(cfg.URL)
	if err != nil {
		log.Fatalf("Build SDM NDEF failed: %v", err)
	}
	fmt.Printf("SDM URL template: %s\n", sdm.URL)

	conn, err := ntag424.Connect(*cfg.Runtime.ReaderIndex)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	fmt.Printf("Using reader [%d]: %s\n", conn.ReaderIdx, conn.Reader)

	if err := ntag424.SelectNDEFApp(conn.Card); err != nil {
		log.Fatalf("SELECT NDEF app failed: %v", err)
	}

	settingsSess, err := ntag424.AuthenticateEV2First(conn.Card, settingsKey, byte(*cfg.Auth.SettingsKeyNo))
	if err != nil {
		log.Fatalf("Settings auth EV2First failed: %v", err)
	}

	fileNo := byte(*cfg.SDM.FileNo)
	sdmKeyNo := byte(*cfg.SDM.SDMKeyNo)

	// Get current file settings to preserve AR values if they're non-standard
	targetAR1 := byte(0x20) // Standard: RW=slot 2, Change=slot 0
	targetAR2 := byte(0xE2) // Standard: Read=free, Write=slot 2
	currentFS, err := ntag424.GetFileSettings(conn.Card, settingsSess, fileNo)
	if err != nil {
		slog.Debug("GetFileSettings failed, using standard AR", "error", err)
	} else {
		targetAR1 = currentFS.AR1
		targetAR2 = currentFS.AR2
		fmt.Println()
		ntag424.PrintFileSettings("CURRENT", fileNo, currentFS)
		fmt.Println()
	}

	// Write NDEF first (while SDM is disabled)
	// Assumes SDM is currently disabled with free write access
	if err := ntag424.WriteNDEFPlain(conn.Card, sdm.NDEF); err != nil {
		log.Fatalf("Write NDEF failed: %v", err)
	}
	fmt.Println("NDEF template written")

	// Now enable SDM
	settingsSess, err = ntag424.AuthenticateEV2First(conn.Card, settingsKey, byte(*cfg.Auth.SettingsKeyNo))
	if err != nil {
		log.Fatalf("Re-auth for SDM enable failed: %v", err)
	}

	fs := &ntag424.FileSettings{
		FileOption: 0x40, // Enable SDM
		AR1:        targetAR1,
		AR2:        targetAR2,
		SDMOptions: 0xC1,
		SDMMeta:    0x0E,
		SDMFile:    sdmKeyNo,
		SDMCtr:     sdmKeyNo,
	}

	ntag424.PrintFileSettings("TARGET", fileNo, fs)
	fmt.Println()

	fmt.Printf("  SDM Offsets:\n")
	fmt.Printf("    UIDOffset:      %d (0x%06X)\n", sdm.UIDOffset, sdm.UIDOffset)
	fmt.Printf("    CtrOffset:      %d (0x%06X)\n", sdm.CtrOffset, sdm.CtrOffset)
	fmt.Printf("    MacInputOffset: %d (0x%06X)\n", sdm.MacInputOffset, sdm.MacInputOffset)
	fmt.Printf("    MacOffset:      %d (0x%06X)\n", sdm.MacOffset, sdm.MacOffset)
	fmt.Println()

	if err := ntag424.ChangeFileSettingsSDM(conn.Card, settingsSess, fileNo, 0x00, fs.AR1, fs.AR2,
		fs.SDMOptions, fs.SDMMeta, fs.SDMFile, fs.SDMCtr,
		sdm.UIDOffset, sdm.CtrOffset, sdm.MacInputOffset, sdm.MacOffset); err != nil {
		log.Fatalf("ChangeFileSettings failed: %v", err)
	}
	fmt.Println("SDM enabled successfully")

	// Read final settings to confirm changes
	finalSess, err := ntag424.AuthenticateEV2First(conn.Card, settingsKey, byte(*cfg.Auth.SettingsKeyNo))
	if err != nil {
		fmt.Printf("\nWarning: could not re-auth for final settings read: %v\n", err)
	} else {
		finalFS, err := ntag424.GetFileSettings(conn.Card, finalSess, fileNo)
		if err != nil {
			fmt.Printf("\nError: could not read final file settings: %v\n", err)
		} else {
			fmt.Println()
			ntag424.PrintFileSettings("FINAL", fileNo, finalFS)
		}
	}

	fmt.Println("\nDone")
}

func runUpdateSDM(configPath string) {
	fmt.Println("========================================")
	fmt.Println("Update SDM Workflow")
	fmt.Println("Step 1: Disable SDM")
	fmt.Println("Step 2: Write NDEF")
	fmt.Println("Step 3: Re-enable SDM")
	fmt.Println("========================================")
	fmt.Println()

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("config load failed: %v", err)
	}

	settingsKey, err := ntag424.LoadKeyHexFile(cfg.Auth.SettingsKeyHexFile)
	if err != nil {
		log.Fatalf("settings key file invalid: %v", err)
	}

	sdm, err := ntag424.BuildSDMNDEF(cfg.URL)
	if err != nil {
		log.Fatalf("Build SDM NDEF failed: %v", err)
	}
	fmt.Printf("SDM URL template: %s\n", sdm.URL)

	conn, err := ntag424.Connect(*cfg.Runtime.ReaderIndex)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	fmt.Printf("Using reader [%d]: %s\n", conn.ReaderIdx, conn.Reader)
	fmt.Println()

	fileNo := byte(*cfg.SDM.FileNo)
	sdmKeyNo := byte(*cfg.SDM.SDMKeyNo)

	// STEP 1: Disable SDM
	fmt.Println("========================================")
	fmt.Println("STEP 1/3: Disabling SDM")
	fmt.Println("========================================")

	if err := ntag424.SelectNDEFApp(conn.Card); err != nil {
		log.Fatalf("SELECT NDEF app failed: %v", err)
	}

	settingsSess, err := ntag424.AuthenticateEV2First(conn.Card, settingsKey, byte(*cfg.Auth.SettingsKeyNo))
	if err != nil {
		log.Fatalf("Settings auth EV2First failed: %v", err)
	}

	// Get current settings to preserve original AR values
	originalAR1 := byte(0x20) // Standard: RW=slot 2, Change=slot 0
	originalAR2 := byte(0xE2) // Standard: Read=free, Write=slot 2
	currentFS, err := ntag424.GetFileSettings(conn.Card, settingsSess, fileNo)
	if err != nil {
		slog.Debug("GetFileSettings failed, using standard AR", "error", err)
	} else {
		originalAR1 = currentFS.AR1
		originalAR2 = currentFS.AR2
		ntag424.PrintFileSettings("CURRENT", fileNo, currentFS)
	}

	// Re-auth before ChangeFileSettings to ensure fresh session
	settingsSess, err = ntag424.AuthenticateEV2First(conn.Card, settingsKey, byte(*cfg.Auth.SettingsKeyNo))
	if err != nil {
		log.Fatalf("Re-auth before ChangeFileSettings failed: %v", err)
	}

	// Set explicit AR values for disabled state (free read/write)
	fsDisable := &ntag424.FileSettings{
		FileOption: 0x00, // Plain communication, SDM disabled
		AR1:        0xE0, // Free read, slot 0 for change settings
		AR2:        0xEE, // Free write (E=free for write, E=free for RW)
		SDMOptions: 0x00,
		SDMMeta:    0x0F,
		SDMFile:    0x0F,
		SDMCtr:     0x0F,
	}

	if err := ntag424.ChangeFileSettingsBasic(conn.Card, settingsSess, fileNo, fsDisable.FileOption, fsDisable.AR1, fsDisable.AR2); err != nil {
		log.Fatalf("Disable SDM failed: %v", err)
	}
	fmt.Println("SDM disabled")
	fmt.Println()

	// STEP 2: Write NDEF
	fmt.Println("========================================")
	fmt.Println("STEP 2/3: Writing NDEF")
	fmt.Println("========================================")

	// Use plain write (no auth) since we set AR2=0xEE (free) in step 1
	if err := ntag424.WriteNDEFPlain(conn.Card, sdm.NDEF); err != nil {
		log.Fatalf("Write NDEF failed: %v", err)
	}
	fmt.Println("NDEF written")
	fmt.Println()

	// STEP 3: Re-enable SDM
	fmt.Println("========================================")
	fmt.Println("STEP 3/3: Re-enabling SDM")
	fmt.Println("========================================")

	if err := ntag424.SelectNDEFApp(conn.Card); err != nil {
		log.Fatalf("SELECT NDEF app failed before re-enable: %v", err)
	}

	settingsSess, err = ntag424.AuthenticateEV2First(conn.Card, settingsKey, byte(*cfg.Auth.SettingsKeyNo))
	if err != nil {
		log.Fatalf("Re-auth for SDM enable failed: %v", err)
	}

	fsEnable := &ntag424.FileSettings{
		FileOption: 0x40,
		AR1:        originalAR1,
		AR2:        originalAR2,
		SDMOptions: 0xC1,
		SDMMeta:    0x0E,
		SDMFile:    sdmKeyNo,
		SDMCtr:     sdmKeyNo,
	}

	ntag424.PrintFileSettings("TARGET", fileNo, fsEnable)
	fmt.Println()

	if err := ntag424.ChangeFileSettingsSDM(conn.Card, settingsSess, fileNo, 0x00, fsEnable.AR1, fsEnable.AR2,
		fsEnable.SDMOptions, fsEnable.SDMMeta, fsEnable.SDMFile, fsEnable.SDMCtr,
		sdm.UIDOffset, sdm.CtrOffset, sdm.MacInputOffset, sdm.MacOffset); err != nil {
		log.Fatalf("Re-enable SDM failed: %v", err)
	}
	fmt.Println("SDM re-enabled")
	fmt.Println()

	// Read final settings to confirm changes
	finalSess, err := ntag424.AuthenticateEV2First(conn.Card, settingsKey, byte(*cfg.Auth.SettingsKeyNo))
	if err != nil {
		fmt.Printf("\nWarning: could not re-auth for final settings read: %v\n", err)
	} else {
		finalFS, err := ntag424.GetFileSettings(conn.Card, finalSess, fileNo)
		if err != nil {
			fmt.Printf("\nError: could not read final file settings: %v\n", err)
		} else {
			fmt.Println()
			fmt.Println("========================================")
			fmt.Println("FINAL SETTINGS")
			fmt.Println("========================================")
			ntag424.PrintFileSettings("FINAL", fileNo, finalFS)
		}
	}

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("Update SDM Complete!")
	fmt.Println("========================================")
}

func runAuthDiagnostics(configPath string) {
	cfg, err := config.LoadWithMode(configPath, config.ValidationAuthDiag)
	if err != nil {
		log.Fatalf("config load failed (diag mode): %v", err)
	}

	settingsKey, err := ntag424.LoadKeyHexFile(cfg.Auth.SettingsKeyHexFile)
	if err != nil {
		log.Fatalf("settings key file invalid: %v", err)
	}

	conn, err := ntag424.Connect(*cfg.Runtime.ReaderIndex)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	fmt.Printf("Running EV2 auth diagnostics on reader [%d]: %s\n", conn.ReaderIdx, conn.Reader)
	fmt.Printf("Configured settings slot: %d\n", *cfg.Auth.SettingsKeyNo)

	slots := make([]byte, 16)
	for i := range slots {
		slots[i] = byte(i)
	}
	results := ntag424.DiagnoseAuthSlots(conn.Card, settingsKey, slots)

	matches := make([]int, 0)
	for _, r := range results {
		if r.Success {
			fmt.Printf("slot=%02d status=ok\n", r.Slot)
			matches = append(matches, int(r.Slot))
			continue
		}
		if r.Step != "" {
			fmt.Printf("slot=%02d status=fail step=%s sw=%04X resp_len=%d\n", r.Slot, r.Step, r.SW, r.RespLen)
			continue
		}
		fmt.Printf("slot=%02d status=fail err=%v\n", r.Slot, r.Err)
	}

	fmt.Printf("matches=%v\n", matches)
	if len(matches) > 0 {
		configured := *cfg.Auth.SettingsKeyNo
		matchConfigured := false
		for _, m := range matches {
			if m == configured {
				matchConfigured = true
				break
			}
		}
		if !matchConfigured {
			fmt.Printf("recommended_settings_key_no=%d\n", matches[0])
		}
		return
	}

	fmt.Println("likely_causes=\"wrong key file, wrong tag, diversified key, or stale config\"")
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
