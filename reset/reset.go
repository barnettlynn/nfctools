package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/barnettlynn/nfctools/pkg/ntag424"
)

const (
	counterFileNo    = 0x02
	ndefFileNo       = 0x01 // NDEF file number (file 1, ID 0xE104)
	authDefaultKeyNo = 0x00
)

// tryChangeKey attempts to change a key slot, trying primaryOld first, then falling back to altOld if different.
// On fallback, re-authenticates with authKey to get a fresh session before retrying.
// Returns the (possibly refreshed) session for subsequent operations.
func tryChangeKey(conn *ntag424.Connection, sess *ntag424.Session, keyNo byte, newKey, primaryOld, altOld, authKey []byte) (*ntag424.Session, error) {
	// Try with primary old key first (use keyVersion 0x00 for factory defaults)
	err := ntag424.ChangeKey(conn, sess, keyNo, newKey, primaryOld, 0x00, authDefaultKeyNo)
	if err == nil {
		return sess, nil
	}

	// If altOld is the same as primaryOld, no point in retrying
	if bytes.Equal(primaryOld, altOld) {
		return sess, err
	}

	// Capture original error before fallback
	origErr := err

	// Re-authenticate to get a fresh session
	if err := ntag424.SelectNDEFApp(conn); err != nil {
		return sess, fmt.Errorf("fallback re-select: %w (original error: %v)", err, origErr)
	}
	newSess, err := ntag424.AuthenticateEV2First(conn, authKey, authDefaultKeyNo)
	if err != nil {
		return sess, fmt.Errorf("fallback re-auth: %w (original error: %v)", err, origErr)
	}

	// Retry with alternative old key (use keyVersion 0x00 for factory defaults)
	err = ntag424.ChangeKey(conn, newSess, keyNo, newKey, altOld, 0x00, authDefaultKeyNo)
	if err != nil {
		return newSess, err
	}

	return newSess, nil
}

// resetTag resets an NTAG 424 DNA tag to factory defaults by reversing all minter changes.
//
// Steps:
//  1. Get UID
//  2. Read current NDEF (non-fatal)
//  3. Read file 2 settings (non-fatal)
//  4. Select NDEF app
//  5. Authenticate with app master key (slot 0)
//  6. Reset file 2 settings to Write=free (temporary, for NDEF clear)
//  7. Clear NDEF data (non-fatal)
//  8. Reset key slot 1 to zeros
//  9. Reset key slot 2 to zeros
// 10. Reset key slot 3 to zeros
// 11. Reset key slot 4 to zeros
// 12. Reset key slot 0 to zeros (invalidates session)
// 13. Restore all file settings to factory defaults
// 14. Verify file settings
func resetTag(conn *ntag424.Connection, appMasterKey, sdmKey, ndefKey, fileThreeKey []byte) error {
	// 1) Get UID
	uid, err := ntag424.GetUID(conn)
	if err != nil {
		return fmt.Errorf("get UID: %w", err)
	}
	uidHex := strings.ToUpper(hex.EncodeToString(uid))
	fmt.Printf("Tag UID: %s\n", uidHex)

	// 2) Read current NDEF (capture "before" state)
	fmt.Println("\nReading current NDEF...")
	beforeNDEF, err := ntag424.ReadNDEF(conn)
	if err != nil {
		fmt.Printf("Warning: could not read NDEF (will continue): %v\n", err)
	} else {
		fmt.Printf("Current NDEF length: %d bytes\n", len(beforeNDEF))
	}

	// 3) Read file 2 settings (capture "before" state)
	fmt.Println("\nReading current file 2 settings...")
	beforeSettings, err := ntag424.GetFileSettingsPlain(conn, counterFileNo)
	if err != nil {
		fmt.Printf("Warning: could not read file settings (will continue): %v\n", err)
	} else {
		fmt.Println("Current file 2 settings:")
		ntag424.PrintFileSettings("", counterFileNo, beforeSettings)
	}

	// 4) Select NDEF application
	if err := ntag424.SelectNDEFApp(conn); err != nil {
		return fmt.Errorf("select NDEF app: %w", err)
	}

	// 5) Authenticate with app master key (slot 0), with fallback to zeros
	sess, authKey, _, err := ntag424.AuthenticateWithFallback(conn, appMasterKey, authDefaultKeyNo, authDefaultKeyNo)
	if err != nil {
		return fmt.Errorf("authenticate with fallback: %w", err)
	}
	zeroKey := make([]byte, 16)
	provisioned := !bytes.Equal(authKey, zeroKey)
	if provisioned {
		fmt.Println("\nAuthenticated with app master key (slot 0) - tag is provisioned")
	} else {
		fmt.Println("\nAuthenticated with factory zeros (slot 0) - tag is at factory defaults")
	}

	// 6) Reset file 2 (NDEF file, ID 0xE104) settings to factory defaults with free write access
	// Factory: FileOption=0x00, AR1=0x00, AR2=0xEE
	// AR1: RW=0, CAR=0
	// AR2: R=0xE (free), W=0xE (free) - allows unauthenticated NDEF clear
	fmt.Println("\nResetting file 2 (NDEF, ID 0xE104) settings to factory defaults (with free write)...")
	const (
		fileOption = 0x00
		ar1        = 0x00 // RW=0, CAR=0
		ar2        = 0xEE // R=free (0xE), W=free (0xE)
	)
	if err := ntag424.ChangeFileSettingsBasic(conn, sess, counterFileNo, fileOption, ar1, ar2); err != nil {
		return fmt.Errorf("reset file 2 settings: %w", err)
	}
	fmt.Println("File 2 settings reset to factory defaults (free write)")

	// 7) Clear NDEF data using ISO write (file 2 now has Write=free after step 6)
	fmt.Println("\nClearing NDEF data...")
	emptyNDEF := []byte{0x00, 0x00} // NLEN=0
	if err := ntag424.WriteNDEFPlain(conn, emptyNDEF); err != nil {
		fmt.Printf("Warning: could not clear NDEF (will continue): %v\n", err)
	} else {
		fmt.Println("NDEF data cleared")
	}

	// Re-authenticate after NDEF clear (session may have been affected)
	fmt.Println("\nRe-authenticating after NDEF clear...")
	if err := ntag424.SelectNDEFApp(conn); err != nil {
		return fmt.Errorf("re-select NDEF app: %w", err)
	}
	sess, err = ntag424.AuthenticateEV2First(conn, authKey, authDefaultKeyNo)
	if err != nil {
		return fmt.Errorf("re-authenticate: %w", err)
	}
	fmt.Println("Re-authenticated successfully")

	// 8) Reset key slot 1 to zeros (cross-slot change)
	fmt.Println("\nResetting key slot 1 to factory zeros...")
	var primaryOld1, altOld1 []byte
	if provisioned {
		primaryOld1, altOld1 = sdmKey, zeroKey
	} else {
		primaryOld1, altOld1 = zeroKey, sdmKey
	}
	sess, err = tryChangeKey(conn, sess, 0x01, zeroKey, primaryOld1, altOld1, authKey)
	if err != nil {
		return fmt.Errorf("reset key slot 1: %w", err)
	}
	fmt.Println("Key slot 1 reset to zeros")

	// 9) Reset key slot 2 to zeros (cross-slot change)
	fmt.Println("Resetting key slot 2 to factory zeros...")
	var primaryOld2, altOld2 []byte
	if provisioned {
		primaryOld2, altOld2 = ndefKey, zeroKey
	} else {
		primaryOld2, altOld2 = zeroKey, ndefKey
	}
	sess, err = tryChangeKey(conn, sess, 0x02, zeroKey, primaryOld2, altOld2, authKey)
	if err != nil {
		return fmt.Errorf("reset key slot 2: %w", err)
	}
	fmt.Println("Key slot 2 reset to zeros")

	// 10) Reset key slot 3 to factory zeros (cross-slot change)
	fmt.Println("Resetting key slot 3 to factory zeros...")
	var primaryOld3, altOld3 []byte
	if provisioned {
		primaryOld3, altOld3 = fileThreeKey, zeroKey
	} else {
		primaryOld3, altOld3 = zeroKey, fileThreeKey
	}
	sess, err = tryChangeKey(conn, sess, 0x03, zeroKey, primaryOld3, altOld3, authKey)
	if err != nil {
		return fmt.Errorf("reset key slot 3: %w", err)
	}
	fmt.Println("Key slot 3 reset to zeros")

	// 11) Reset key slot 4 to factory zeros
	fmt.Println("Resetting key slot 4 to factory zeros...")
	if err := ntag424.ChangeKey(conn, sess, 0x04, zeroKey, zeroKey, 0x00, authDefaultKeyNo); err != nil {
		return fmt.Errorf("reset key slot 4: %w", err)
	}
	fmt.Println("Key slot 4 reset to zeros")

	// 12) Reset key slot 0 to zeros (same-slot change, invalidates session)
	fmt.Println("Resetting key slot 0 to factory zeros...")
	if provisioned {
		if err := ntag424.ChangeKeySame(conn, sess, 0x00, zeroKey, 0x00); err != nil {
			return fmt.Errorf("reset key slot 0: %w", err)
		}
		fmt.Println("Key slot 0 reset to zeros (session invalidated)")
	} else {
		fmt.Println("Key slot 0 already at factory zeros (skipped)")
	}

	// 13) Restore all file settings to factory defaults
	fmt.Println("\nRestoring file settings to factory defaults...")
	if err := ntag424.SelectNDEFApp(conn); err != nil {
		return fmt.Errorf("re-select for file settings restore: %w", err)
	}
	sess, err = ntag424.AuthenticateEV2First(conn, zeroKey, authDefaultKeyNo)
	if err != nil {
		return fmt.Errorf("re-auth for file settings restore: %w", err)
	}

	// File 1 (CC): FileOption=0x00, AR1=0x00, AR2=0xE0
	if err := ntag424.ChangeFileSettingsBasic(conn, sess, 0x01, 0x00, 0x00, 0xE0); err != nil {
		return fmt.Errorf("restore file 1 settings: %w", err)
	}
	fmt.Println("File 1 (CC) settings restored to factory defaults")

	// File 2 (NDEF): FileOption=0x00, AR1=0x00, AR2=0xE0
	if err := ntag424.ChangeFileSettingsBasic(conn, sess, counterFileNo, 0x00, 0x00, 0xE0); err != nil {
		return fmt.Errorf("restore file 2 settings: %w", err)
	}
	fmt.Println("File 2 (NDEF) settings restored to factory defaults")

	// File 3 (Proprietary): FileOption=0x03, AR1=0x00, AR2=0x00
	if err := ntag424.ChangeFileSettingsBasic(conn, sess, 0x03, 0x03, 0x00, 0x00); err != nil {
		return fmt.Errorf("restore file 3 settings: %w", err)
	}
	fmt.Println("File 3 (Proprietary) settings restored to factory defaults")

	// 14) Verify file settings (after re-selecting app)
	fmt.Println("\nVerifying file settings...")
	var afterSettings *ntag424.FileSettings
	if err := ntag424.SelectNDEFApp(conn); err != nil {
		fmt.Printf("Warning: could not re-select app for verification: %v\n", err)
	} else {
		afterSettings, err = ntag424.GetFileSettingsPlain(conn, counterFileNo)
		if err != nil {
			fmt.Printf("Warning: could not verify file settings: %v\n", err)
		} else {
			fmt.Println("Verified file 2 settings:")
			ntag424.PrintFileSettings("", counterFileNo, afterSettings)
		}
	}

	// Print summary
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("RESET SUMMARY")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("Tag UID: %s\n", uidHex)
	fmt.Println("\nKeys reset:")
	if provisioned {
		fmt.Println("  ✓ Slot 0 (App Master Key) → factory zeros")
		fmt.Println("  ✓ Slot 1 (SDM Key) → factory zeros")
		fmt.Println("  ✓ Slot 2 (NDEF Write Key) → factory zeros")
		fmt.Println("  ✓ Slot 3 → factory zeros")
		fmt.Println("  ✓ Slot 4 → factory zeros")
	} else {
		fmt.Println("  ✓ Slot 0 (App Master Key) → already at factory zeros")
		fmt.Println("  ✓ Slot 1 (SDM Key) → reset to factory zeros")
		fmt.Println("  ✓ Slot 2 (NDEF Write Key) → reset to factory zeros")
		fmt.Println("  ✓ Slot 3 → reset to factory zeros")
		fmt.Println("  ✓ Slot 4 → reset to factory zeros")
	}
	fmt.Println("\nFile settings restored:")
	fmt.Println("  ✓ File 1 (CC): FileOption=0x00, AR1=0x00, AR2=0xE0")
	fmt.Println("  ✓ File 2 (NDEF): FileOption=0x00, AR1=0x00, AR2=0xE0")
	fmt.Println("  ✓ File 3 (Proprietary): FileOption=0x03, AR1=0x00, AR2=0x00")
	if beforeSettings != nil {
		fmt.Println("\nFile 2 settings (before):")
		ntag424.PrintFileSettings("    ", counterFileNo, beforeSettings)
	}
	if afterSettings != nil {
		fmt.Println("\nFile 2 settings (after):")
		ntag424.PrintFileSettings("    ", counterFileNo, afterSettings)
	}
	fmt.Println("\nNDEF:")
	fmt.Println("  ✓ NDEF data cleared (NLEN=0)")
	fmt.Println(strings.Repeat("=", 60))

	return nil
}
