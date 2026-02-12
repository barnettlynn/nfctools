package main

import (
	"fmt"
	"path/filepath"

	"github.com/ebfe/scard"
)

func containsByte(slice []byte, val byte) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

func probeAuthKeySlots(card *scard.Card, key []byte, slots []byte) []byte {
	if len(key) != 16 {
		return nil
	}
	var matches []byte
	for _, slot := range slots {
		if _, err := authenticateEV2First(card, key, slot); err == nil {
			matches = append(matches, slot)
		}
	}
	return matches
}

func probeAuthKey(card *scard.Card, key []byte) []byte {
	if len(key) != 16 {
		return nil
	}
	var matches []byte
	for i := 0; i < 16; i++ {
		if _, err := authenticateEV2First(card, key, byte(i)); err == nil {
			matches = append(matches, byte(i))
		}
	}
	return matches
}

func printSlotStatus(role string, slotNo byte, keyMatches []byte, keyLabel string, ntag424Matches []byte, zeroMatches []byte) {
	status := "unknown"
	label := ""

	// Check if this slot matched the provisioned key
	for _, m := range keyMatches {
		if m == slotNo {
			status = "provisioned"
			label = keyLabel
			break
		}
	}

	// If not provisioned, check if it matched the ntag424 key
	if status == "unknown" {
		for _, m := range ntag424Matches {
			if m == slotNo {
				status = "provisioned"
				label = "../keys/ntag424_key1_new.hex"
				break
			}
		}
	}

	// If not provisioned, check if it matched the all-zero key
	if status == "unknown" {
		for _, m := range zeroMatches {
			if m == slotNo {
				status = "default"
				label = "all-zero key"
				break
			}
		}
	}

	// If keyLabel is empty, the key file wasn't loaded
	if keyLabel == "" && status == "unknown" {
		status = "not tested"
		label = "key file not found"
	}

	fmt.Printf("    Slot %d (%s):  %-12s  (%s)\n", slotNo, role, status, label)
}

func accessLabel(keyNo byte, cfg *readerConfig) string {
	switch keyNo {
	case 0x0E:
		return "no key needed   (free)"
	case 0x0F:
		return "denied          (never)"
	default:
		// Add role label if this matches a known key slot
		roleLabel := ""
		if keyNo == cfg.authKeyNo {
			roleLabel = " <- AppMasterKey"
		} else if keyNo == cfg.sdmKeyNo {
			roleLabel = " <- SDM key"
		} else if keyNo == cfg.ndefKeyNo {
			roleLabel = " <- File Two Write key"
		}
		return fmt.Sprintf("Key slot %d      %s", keyNo, roleLabel)
	}
}

func printProvisioningCheck(card *scard.Card, cfg *readerConfig, macVerified bool) {
	fmt.Println("Provisioning check:")

	// Probe key slots for each key file
	var cfgMatches, sdmMatches, ndefMatches, ntag424Matches, zeroMatches []byte

	// Load additional key files
	ndefKey := loadOptionalKey(filepath.Join("..", "keys", "FileTwoWrite.hex"))
	ntag424Key := loadOptionalKey(filepath.Join("..", "keys", "ntag424_key1_new.hex"))

	if cfg.fullProbe {
		// Full probe: try all 16 slots for each key
		cfgMatches = probeAuthKey(card, cfg.authKey)
		sdmMatches = probeAuthKey(card, cfg.sdmKey)
		ndefMatches = probeAuthKey(card, ndefKey)
		ntag424Matches = probeAuthKey(card, ntag424Key)
		zeroMatches = probeAuthKey(card, make([]byte, 16))
	} else {
		// Default: probe only expected slots
		cfgMatches = probeAuthKeySlots(card, cfg.authKey, []byte{cfg.authKeyNo})
		sdmMatches = probeAuthKeySlots(card, cfg.sdmKey, []byte{cfg.sdmKeyNo})
		ndefMatches = probeAuthKeySlots(card, ndefKey, []byte{cfg.ndefKeyNo})
		ntag424Matches = probeAuthKeySlots(card, ntag424Key, []byte{cfg.authKeyNo, cfg.sdmKeyNo, cfg.ndefKeyNo})
		zeroMatches = probeAuthKeySlots(card, make([]byte, 16), []byte{cfg.authKeyNo, cfg.sdmKeyNo, cfg.ndefKeyNo})
	}

	// --- Key slots section ---
	fmt.Println("\n  Key slots:")
	printSlotStatus("AppMaster", cfg.authKeyNo, cfgMatches, cfg.authKeyLabel, ntag424Matches, zeroMatches)
	printSlotStatus("SDM", cfg.sdmKeyNo, sdmMatches, cfg.sdmKeyLabel, ntag424Matches, zeroMatches)
	printSlotStatus("File Two Write", cfg.ndefKeyNo, ndefMatches, cfg.ndefKeyLabel, ntag424Matches, zeroMatches)

	// Decide which key to use for FileSettings: prefer config key, then ntag424 key, then all-zero.
	var usedKey []byte
	var usedKeyNo byte
	var usedKeyLabel string
	if len(cfgMatches) > 0 {
		usedKey = cfg.authKey
		usedKeyNo = cfgMatches[0]
		usedKeyLabel = cfg.authKeyLabel
	} else if len(ntag424Matches) > 0 && containsByte(ntag424Matches, cfg.authKeyNo) {
		// Use ntag424 key if it matches slot 0 (AppMasterKey slot)
		usedKey = ntag424Key
		usedKeyNo = cfg.authKeyNo
		usedKeyLabel = "../ntag424_key1_new.hex"
	} else if len(zeroMatches) > 0 {
		usedKey = make([]byte, 16)
		usedKeyNo = zeroMatches[0]
		usedKeyLabel = "all-zero key"
	}

	if usedKey == nil {
		fmt.Println("\n  Error: Cannot read file settings (no key matched)")
		return
	}

	// Attempt authentication with the selected key
	fmt.Printf("\n  Attempting file settings read with: %s (slot %d)\n", usedKeyLabel, usedKeyNo)
	sess, err := authenticateEV2First(card, usedKey, usedKeyNo)
	if err != nil {
		fmt.Printf("  Error: Auth failed (%v)\n", err)
		return
	}

	fs, err := getFileSettingsSecure(card, sess, cfg.fileNo)
	if err != nil {
		fsPlain, perr := getFileSettingsPlain(card, cfg.fileNo)
		if perr != nil {
			fmt.Printf("\n  Error: Cannot read file %d settings (%v)\n", cfg.fileNo, perr)

			// Diagnostic: Try reading files 1, 2, and 3
			fmt.Println("\n  Diagnostic: Attempting to read all file settings...")
			for fileNo := byte(1); fileNo <= 3; fileNo++ {
				fmt.Printf("    File %d: ", fileNo)

				// Try secure read first
				diagFS, diagErr := getFileSettingsSecure(card, sess, fileNo)
				if diagErr == nil {
					fmt.Printf("OK (secure) - AR1=%02X AR2=%02X\n", diagFS.ar1, diagFS.ar2)
					if fileNo == cfg.fileNo {
						fs = diagFS
					}
					continue
				}

				// Try plain read
				diagFSPlain, diagErrPlain := getFileSettingsPlain(card, fileNo)
				if diagErrPlain == nil {
					fmt.Printf("OK (plain) - AR1=%02X AR2=%02X\n", diagFSPlain.ar1, diagFSPlain.ar2)
					if fileNo == cfg.fileNo {
						fs = diagFSPlain
					}
					continue
				}

				fmt.Printf("FAIL (%v)\n", diagErrPlain)
			}

			if fs == nil {
				fmt.Println("\n  All file reads failed. Cannot display access rights.")
				return
			}
			fmt.Printf("\n  Successfully read file %d from diagnostic scan.\n", cfg.fileNo)
		} else {
			fs = fsPlain
		}
	}

	// Parse file settings
	sdmEnabled := (fs.fileOption & 0x40) != 0
	commMode := fs.fileOption & 0x03
	rw := (fs.ar1 >> 4) & 0x0F
	car := fs.ar1 & 0x0F
	r := (fs.ar2 >> 4) & 0x0F
	w := fs.ar2 & 0x0F

	// --- File access rights section ---
	fmt.Printf("\n  File %d access rights:              [raw: %02X %02X]\n", cfg.fileNo, fs.ar1, fs.ar2)
	fmt.Printf("    Read data:        %s\n", accessLabel(r, cfg))
	fmt.Printf("    Write data:       %s\n", accessLabel(w, cfg))
	fmt.Printf("    Read+Write:       %s\n", accessLabel(rw, cfg))
	fmt.Printf("    Change settings:  %s\n", accessLabel(car, cfg))

	// --- SDM config section ---
	if sdmEnabled {
		fmt.Printf("\n  SDM config:                         [enabled, CommMode %d, opts 0x%02X]\n", commMode, fs.sdmOptions)
		fmt.Printf("    MAC generation:   %s\n", accessLabel(fs.sdmFile, cfg))
		fmt.Printf("    Counter read:     %s\n", accessLabel(fs.sdmCtr, cfg))
		fmt.Printf("    Meta read:        %s\n", accessLabel(fs.sdmMeta, cfg))
	} else {
		fmt.Println("\n  SDM config:                         [disabled]")
	}
}

func loadOptionalKey(path string) []byte {
	key, err := loadKeyHexFile(path)
	if err != nil {
		return nil
	}
	return key
}
