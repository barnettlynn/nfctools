package main

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/barnettlynn/nfctools/pkg/ntag424"
)

func deriveSDMSessionKey(baseKey, uid, ctrLE []byte) ([]byte, error) {
	return ntag424.DeriveSDMSessionKey(baseKey, uid, ctrLE)
}

func parseSDMURL(raw string) (uid, ctr, mac string, err error) {
	return ntag424.ParseSDMURL(raw)
}

func printSDMVerify(rawURL string, key []byte, keyLabel string, keyNo byte) bool {
	fmt.Println("SDM verify:")
	uid, ctr, mac, err := parseSDMURL(rawURL)
	if err != nil {
		fmt.Printf("  X invalid URL params: %v\n", err)
		return false
	}

	uidLenOK := len(uid) == 14
	ctrLenOK := len(ctr) == 6
	macLenOK := len(mac) == 16

	fmt.Printf("  uid length (14 hex): %s\n", okX(uidLenOK))
	fmt.Printf("  ctr length (6 hex): %s\n", okX(ctrLenOK))
	fmt.Printf("  mac length (16 hex): %s\n", okX(macLenOK))

	macInput := fmt.Sprintf("uid=%s&ctr=%s&mac=", uid, ctr)
	fmt.Printf("  MAC input: %s\n", macInput)

	if len(key) == 0 {
		keyPath, err := findDefaultKeyFile()
		if err != nil {
			fmt.Printf("  X key file: %v\n", err)
			return false
		}
		keyLabel = keyPath
		key, err = loadKeyHexFile(keyPath)
		if err != nil {
			fmt.Printf("  X key file (%s): %v\n", keyPath, err)
			return false
		}
	}
	if keyLabel == "" {
		keyLabel = "(inline)"
	}
	fmt.Printf("  MAC key (KeyNo %X): %s\n", keyNo, keyLabel)

	uidBytes, err := hex.DecodeString(uid)
	if err != nil {
		fmt.Printf("  X UID hex decode: %v\n", err)
		return false
	}
	if len(uidBytes) != 7 {
		fmt.Printf("  X UID length bytes: got %d, want 7\n", len(uidBytes))
		return false
	}

	ctrBytesBE, err := hex.DecodeString(ctr)
	if err != nil {
		fmt.Printf("  X CTR hex decode: %v\n", err)
		return false
	}
	if len(ctrBytesBE) != 3 {
		fmt.Printf("  X CTR length bytes: got %d, want 3\n", len(ctrBytesBE))
		return false
	}

	// Use shared library's VerifySDMMACDetailed for verification
	match, counter, computed, err := ntag424.VerifySDMMACDetailed(rawURL, key)
	if err != nil {
		fmt.Printf("  X verification error: %v\n", err)
		return false
	}

	fmt.Printf("  Computed MAC: %s\n", computed)
	fmt.Printf("  Expected MAC: %s\n", strings.ToUpper(mac))
	fmt.Printf("  MAC match: %s\n", okX(match))
	fmt.Printf("  Counter: %d (0x%06X)\n", counter, counter)
	return match
}
