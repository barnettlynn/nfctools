package main

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/barnettlynn/nfctools/pkg/ntag424"
)

const (
	counterFileNo    = 0x02
	authDefaultKeyNo = 0x00
)

// provisionTag provisions an NTAG 424 DNA tag with the specified keys and SDM configuration.
// It follows the modern pattern using direct ntag424 package calls.
//
// Steps:
//  1. Get UID
//  2. Select NDEF app
//  3. Authenticate with factory zero key (slot 0)
//  4. Change keys: SDM (slot 1), NDEF write (slot 2), App master (slot 0)
//  5. Build SDM NDEF template
//  6. Re-authenticate with new app master key
//  7. Configure SDM file settings
//  8. Write NDEF template
//
// Returns the tag UID as a hex string (uppercase) on success.
func provisionTag(conn *ntag424.Connection, appMasterKey, sdmKey, ndefKey []byte, baseURL string) (string, error) {
	// 1) Get UID
	uid, err := ntag424.GetUID(conn)
	if err != nil {
		return "", fmt.Errorf("get UID: %w", err)
	}
	uidHex := strings.ToUpper(hex.EncodeToString(uid))

	// 2) Select NDEF application
	if err := ntag424.SelectNDEFApp(conn); err != nil {
		return "", fmt.Errorf("select NDEF app: %w", err)
	}

	// 3) Authenticate with factory zero key (slot 0)
	zeroKey := make([]byte, 16)
	sess, err := ntag424.AuthenticateEV2First(conn, zeroKey, authDefaultKeyNo)
	if err != nil {
		return "", fmt.Errorf("authenticate with factory key: %w", err)
	}

	// 4) Change keys: SDM (slot 1), NDEF write (slot 2), App master (slot 0)
	// Change slot 1 (SDM key)
	if err := ntag424.ChangeKey(conn, sess, 0x01, sdmKey, zeroKey, 0x01, authDefaultKeyNo); err != nil {
		return "", fmt.Errorf("change key slot 1 (SDM): %w", err)
	}

	// Change slot 2 (NDEF write key)
	if err := ntag424.ChangeKey(conn, sess, 0x02, ndefKey, zeroKey, 0x01, authDefaultKeyNo); err != nil {
		return "", fmt.Errorf("change key slot 2 (NDEF write): %w", err)
	}

	// Change slot 0 (app master key) - uses current auth key as old key
	if err := ntag424.ChangeKey(conn, sess, 0x00, appMasterKey, zeroKey, 0x01, authDefaultKeyNo); err != nil {
		return "", fmt.Errorf("change key slot 0 (app master): %w", err)
	}

	// 5) Build SDM NDEF template
	sdm, err := ntag424.BuildSDMNDEF(baseURL)
	if err != nil {
		return "", fmt.Errorf("build SDM NDEF: %w", err)
	}

	// 6) Re-authenticate with new app master key (session is invalidated after changing slot 0)
	sess, err = ntag424.AuthenticateEV2First(conn, appMasterKey, 0x00)
	if err != nil {
		return "", fmt.Errorf("re-authenticate with new app master key: %w", err)
	}

	// 7) Configure SDM file settings
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

	// 8) Write NDEF template (plain)
	if err := ntag424.WriteNDEFPlain(conn, sdm.NDEF); err != nil {
		return "", fmt.Errorf("write NDEF: %w", err)
	}

	return uidHex, nil
}
