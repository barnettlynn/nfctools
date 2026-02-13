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
	ndefFileNo       = 0x01 // NDEF file number (different from counterFileNo)
	authDefaultKeyNo = 0x00
)

// provisionTag provisions an NTAG 424 DNA tag with the specified keys and SDM configuration.
// Handles tags in factory default state (all keys = zeros) regardless of File 2 access rights.
//
// Steps:
//  1. Get UID
//  2. Build SDM NDEF template
//  3. Authenticate with zero key and set File 2 to Write=free (if needed)
//  4. Write NDEF using plain write
//  5. Select NDEF app
//  6. Re-authenticate with factory zero key (slot 0) to enable key changes
//  7. Change keys: SDM (slot 1), NDEF write (slot 2), App master (slot 0)
//  8. Re-select NDEF app
//  9. Re-authenticate with new app master key
// 10. Configure SDM file settings
//
// Returns the tag UID as a hex string (uppercase) on success.
func provisionTag(conn *ntag424.Connection, appMasterKey, sdmKey, ndefKey []byte, baseURL string) (string, error) {
	// 1) Get UID
	uid, err := ntag424.GetUID(conn)
	if err != nil {
		return "", fmt.Errorf("get UID: %w", err)
	}
	uidHex := strings.ToUpper(hex.EncodeToString(uid))

	// 2) Build SDM NDEF template
	sdm, err := ntag424.BuildSDMNDEF(baseURL)
	if err != nil {
		return "", fmt.Errorf("build SDM NDEF: %w", err)
	}

	// 3) Ensure tag is at factory defaults before provisioning
	// Try to authenticate - if tag is provisioned, reset it first
	zeroKey := make([]byte, 16)
	if err := ntag424.SelectNDEFApp(conn); err != nil {
		return "", fmt.Errorf("select NDEF app for prep: %w", err)
	}
	sess, authKey, _, err := ntag424.AuthenticateWithFallback(conn, appMasterKey, authDefaultKeyNo, authDefaultKeyNo)
	if err != nil {
		return "", fmt.Errorf("authenticate for prep: %w", err)
	}

	// Determine if tag is provisioned by checking which key authenticated
	provisioned := !bytes.Equal(authKey, zeroKey)

	// If tag is provisioned, reset it to factory defaults
	if provisioned {
		// Reset all keys to zeros
		if err := ntag424.ChangeKey(conn, sess, 0x01, zeroKey, sdmKey, 0x00, authDefaultKeyNo); err != nil {
			return "", fmt.Errorf("reset key slot 1: %w", err)
		}
		if err := ntag424.ChangeKey(conn, sess, 0x02, zeroKey, ndefKey, 0x00, authDefaultKeyNo); err != nil {
			return "", fmt.Errorf("reset key slot 2: %w", err)
		}
		if err := ntag424.ChangeKeySame(conn, sess, 0x00, zeroKey, 0x00); err != nil {
			return "", fmt.Errorf("reset key slot 0: %w", err)
		}

		// Re-authenticate with zero key
		if err := ntag424.SelectNDEFApp(conn); err != nil {
			return "", fmt.Errorf("re-select after reset: %w", err)
		}
		sess, err = ntag424.AuthenticateEV2First(conn, zeroKey, authDefaultKeyNo)
		if err != nil {
			return "", fmt.Errorf("re-auth after reset: %w", err)
		}
		authKey = zeroKey
	}

	// Set File 2 to Write=free (AR2=0xEE) to allow unauthenticated NDEF write
	if err := ntag424.ChangeFileSettingsBasic(conn, sess, counterFileNo, 0x00, 0x00, 0xEE); err != nil {
		return "", fmt.Errorf("set file 2 write=free: %w", err)
	}

	_ = authKey // Mark as used

	// 4) Write NDEF using plain write (now Write=free is guaranteed)
	// WriteNDEFPlain selects NDEF app and file, then writes using ISO UPDATE BINARY
	if err := ntag424.WriteNDEFPlain(conn, sdm.NDEF); err != nil {
		return "", fmt.Errorf("write NDEF: %w", err)
	}

	// 5) Select NDEF application to set up for authentication
	// (WriteNDEFPlain already selected it, but being explicit for clarity)
	if err := ntag424.SelectNDEFApp(conn); err != nil {
		return "", fmt.Errorf("select NDEF app for auth: %w", err)
	}

	// 6) Re-authenticate with factory zero key (slot 0) to change keys
	sess, err = ntag424.AuthenticateEV2First(conn, zeroKey, authDefaultKeyNo)
	if err != nil {
		return "", fmt.Errorf("authenticate with factory key: %w", err)
	}

	// 7) Change keys: SDM (slot 1), NDEF write (slot 2), App master (slot 0)
	// Change slot 1 (SDM key)
	if err := ntag424.ChangeKey(conn, sess, 0x01, sdmKey, zeroKey, 0x01, authDefaultKeyNo); err != nil {
		return "", fmt.Errorf("change key slot 1 (SDM): %w", err)
	}

	// Change slot 2 (NDEF write key)
	if err := ntag424.ChangeKey(conn, sess, 0x02, ndefKey, zeroKey, 0x01, authDefaultKeyNo); err != nil {
		return "", fmt.Errorf("change key slot 2 (NDEF write): %w", err)
	}

	// Change slot 0 (app master key) - uses current auth key as old key
	if err := ntag424.ChangeKeySame(conn, sess, 0x00, appMasterKey, 0x01); err != nil {
		return "", fmt.Errorf("change key slot 0 (app master): %w", err)
	}

	// 8) Re-select NDEF app (required before re-authenticating)
	if err := ntag424.SelectNDEFApp(conn); err != nil {
		return "", fmt.Errorf("re-select NDEF app: %w", err)
	}

	// 9) Re-authenticate with new app master key (session is invalidated after changing slot 0)
	sess, err = ntag424.AuthenticateEV2First(conn, appMasterKey, 0x00)
	if err != nil {
		return "", fmt.Errorf("re-authenticate with new app master key: %w", err)
	}

	// 10) Configure SDM file settings
	// Access rights: RW=0x02, CAR=0x00, R=0x0E (free), W=0x02
	const (
		rwKeyNo  = 0x02
		carKeyNo = 0x00
		rKeyNo   = 0x0E
		wKeyNo   = 0x02
	)
	ar1 := byte((rwKeyNo << 4) | carKeyNo)
	ar2 := byte((rKeyNo << 4) | wKeyNo)

	// SDM options: 0xC1 = UID+ReadCtr mirroring, ASCII encoding
	sdmOptions := byte(0xC1)
	sdmMeta := byte(0x0E)    // plain meta
	sdmFile := byte(0x01)    // SDM file read key
	sdmCtr := byte(0x01)     // SDM counter key

	if err := ntag424.ChangeFileSettingsSDM(conn, sess, counterFileNo, 0x00, ar1, ar2,
		sdmOptions, sdmMeta, sdmFile, sdmCtr,
		sdm.UIDOffset, sdm.CtrOffset, sdm.MacInputOffset, sdm.MacOffset); err != nil {
		return "", fmt.Errorf("change file settings SDM: %w", err)
	}

	return uidHex, nil
}
