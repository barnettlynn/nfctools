package ntag424

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
)

// DeriveSDMSessionKey derives the SDM MAC session key from a base key, UID, and read counter.
// From ro/sdm.go:11-28.
//
// Parameters:
//   - baseKey: 16-byte SDM file read key (typically key slot 1 or 2)
//   - uid: 7-byte UID
//   - ctrLE: 3-byte little-endian read counter
//
// Returns:
//   - 16-byte SDM session key (CMAC of SV2)
//
// SV2 derivation:
//   SV2 = 3C C3 00 01 00 80 || UID(7) || Counter_LE(3)
//   SDMSessionKey = AES-CMAC(baseKey, SV2)
func DeriveSDMSessionKey(baseKey, uid, ctrLE []byte) ([]byte, error) {
	if len(baseKey) != 16 {
		return nil, fmt.Errorf("base key must be 16 bytes, got %d", len(baseKey))
	}
	if len(uid) != 7 {
		return nil, fmt.Errorf("UID must be 7 bytes, got %d", len(uid))
	}
	if len(ctrLE) != 3 {
		return nil, fmt.Errorf("counter must be 3 bytes, got %d", len(ctrLE))
	}

	sv2 := make([]byte, 0, 16)
	sv2 = append(sv2, 0x3C, 0xC3, 0x00, 0x01, 0x00, 0x80)
	sv2 = append(sv2, uid...)
	sv2 = append(sv2, ctrLE...)

	return aesCMAC(baseKey, sv2)
}

// ParseSDMURL extracts uid, ctr, and mac parameters from an SDM URL.
// From ro/sdm.go:30-43.
//
// Returns:
//   - uid: 14-character hex string (7 bytes)
//   - ctr: 6-character hex string (3 bytes big-endian)
//   - mac: 16-character hex string (8 bytes truncated CMAC)
//   - error if parsing fails or parameters are missing
func ParseSDMURL(rawURL string) (uid, ctr, mac string, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", "", err
	}
	q := u.Query()
	uid = q.Get("uid")
	ctr = q.Get("ctr")
	mac = q.Get("mac")
	if uid == "" || ctr == "" || mac == "" {
		return uid, ctr, mac, fmt.Errorf("missing uid/ctr/mac parameters")
	}
	return uid, ctr, mac, nil
}

// VerifySDMMAC verifies the MAC from an SDM URL.
// From ro/sdm.go:45-129 (simplified for library use).
//
// Parameters:
//   - rawURL: Full SDM URL with uid, ctr, mac query parameters
//   - sdmFileKey: 16-byte SDM file read key
//
// Returns:
//   - true if MAC matches, false otherwise
//   - error if parsing or derivation fails
//
// Steps:
//   1. Parse uid, ctr, mac from URL
//   2. Convert counter from big-endian to little-endian
//   3. Derive SDM session key
//   4. Compute CMAC over "uid=<uid>&ctr=<ctr>&mac="
//   5. Truncate to 8 bytes (odd bytes only)
//   6. Compare with provided MAC
func VerifySDMMAC(rawURL string, sdmFileKey []byte) (bool, error) {
	uid, ctr, mac, err := ParseSDMURL(rawURL)
	if err != nil {
		return false, err
	}

	if len(uid) != 14 || len(ctr) != 6 || len(mac) != 16 {
		return false, fmt.Errorf("invalid parameter lengths: uid=%d ctr=%d mac=%d (want 14,6,16)", len(uid), len(ctr), len(mac))
	}

	// Decode UID
	uidBytes, err := hex.DecodeString(uid)
	if err != nil {
		return false, fmt.Errorf("UID hex decode: %v", err)
	}
	if len(uidBytes) != 7 {
		return false, fmt.Errorf("UID length: got %d bytes, want 7", len(uidBytes))
	}

	// Decode counter (big-endian in URL, little-endian for derivation)
	ctrBytesBE, err := hex.DecodeString(ctr)
	if err != nil {
		return false, fmt.Errorf("CTR hex decode: %v", err)
	}
	if len(ctrBytesBE) != 3 {
		return false, fmt.Errorf("CTR length: got %d bytes, want 3", len(ctrBytesBE))
	}
	ctrBytesLE := []byte{ctrBytesBE[2], ctrBytesBE[1], ctrBytesBE[0]}

	// Derive SDM session key
	sessionKey, err := DeriveSDMSessionKey(sdmFileKey, uidBytes, ctrBytesLE)
	if err != nil {
		return false, fmt.Errorf("session key derive: %v", err)
	}

	// Compute CMAC over MAC input
	macInput := fmt.Sprintf("uid=%s&ctr=%s&mac=", uid, ctr)
	cmac, err := aesCMAC(sessionKey, []byte(macInput))
	if err != nil {
		return false, fmt.Errorf("CMAC error: %v", err)
	}
	computed := truncateOddBytes(cmac)

	// Decode expected MAC
	expectedBytes, err := hex.DecodeString(mac)
	if err != nil || len(expectedBytes) != 8 {
		return false, fmt.Errorf("MAC decode error")
	}

	// Compare
	return bytes.Equal(computed, expectedBytes), nil
}

// VerifySDMMACDetailed verifies the MAC from an SDM URL and returns detailed information.
//
// Returns:
//   - match: true if MAC matches
//   - counter: read counter value (decoded from big-endian)
//   - computedMAC: computed MAC hex string
//   - error: if parsing or derivation fails
func VerifySDMMACDetailed(rawURL string, sdmFileKey []byte) (match bool, counter uint32, computedMAC string, err error) {
	uid, ctr, mac, err := ParseSDMURL(rawURL)
	if err != nil {
		return false, 0, "", err
	}

	if len(uid) != 14 || len(ctr) != 6 || len(mac) != 16 {
		return false, 0, "", fmt.Errorf("invalid parameter lengths: uid=%d ctr=%d mac=%d (want 14,6,16)", len(uid), len(ctr), len(mac))
	}

	// Decode UID
	uidBytes, err := hex.DecodeString(uid)
	if err != nil {
		return false, 0, "", fmt.Errorf("UID hex decode: %v", err)
	}
	if len(uidBytes) != 7 {
		return false, 0, "", fmt.Errorf("UID length: got %d bytes, want 7", len(uidBytes))
	}

	// Decode counter (big-endian in URL, little-endian for derivation)
	ctrBytesBE, err := hex.DecodeString(ctr)
	if err != nil {
		return false, 0, "", fmt.Errorf("CTR hex decode: %v", err)
	}
	if len(ctrBytesBE) != 3 {
		return false, 0, "", fmt.Errorf("CTR length: got %d bytes, want 3", len(ctrBytesBE))
	}
	ctrBytesLE := []byte{ctrBytesBE[2], ctrBytesBE[1], ctrBytesBE[0]}
	counter = uint32(ctrBytesBE[0])<<16 | uint32(ctrBytesBE[1])<<8 | uint32(ctrBytesBE[2])

	// Derive SDM session key
	sessionKey, err := DeriveSDMSessionKey(sdmFileKey, uidBytes, ctrBytesLE)
	if err != nil {
		return false, counter, "", fmt.Errorf("session key derive: %v", err)
	}

	// Compute CMAC over MAC input
	macInput := fmt.Sprintf("uid=%s&ctr=%s&mac=", uid, ctr)
	cmac, err := aesCMAC(sessionKey, []byte(macInput))
	if err != nil {
		return false, counter, "", fmt.Errorf("CMAC error: %v", err)
	}
	computed := truncateOddBytes(cmac)
	computedMAC = strings.ToUpper(hex.EncodeToString(computed))

	// Decode expected MAC
	expectedBytes, err := hex.DecodeString(mac)
	if err != nil || len(expectedBytes) != 8 {
		return false, counter, computedMAC, fmt.Errorf("MAC decode error")
	}

	// Compare
	match = bytes.Equal(computed, expectedBytes)
	return match, counter, computedMAC, nil
}

// GenerateSDMURL generates an SDM URL by simulating what the NTAG 424 DNA tag does on tap.
// This is the inverse of VerifySDMMAC — it computes the MAC from the tag's perspective.
//
// Parameters:
//   - baseURL: Base URL (e.g., "https://api.guideapparel.com/tap")
//   - uid: 7-byte tag UID
//   - counter: SDM read counter value (0-0xFFFFFF)
//   - sdmFileKey: 16-byte SDM file read key
//
// Returns:
//   - Complete SDM URL with uid, ctr, mac query parameters
//   - error if validation fails
//
// The function:
//  1. Validates inputs (uid=7 bytes, sdmFileKey=16 bytes, counter <= 0xFFFFFF)
//  2. Encodes UID as uppercase hex (14 chars)
//  3. Encodes counter as 3-byte big-endian uppercase hex (6 chars)
//  4. Derives SDM session key
//  5. Computes CMAC over "uid=<UID>&ctr=<CTR>&mac="
//  6. Truncates CMAC to 8 bytes (odd bytes only)
//  7. Builds final URL preserving any existing query parameters
func GenerateSDMURL(baseURL string, uid []byte, counter uint32, sdmFileKey []byte) (string, error) {
	// Validate inputs
	if len(uid) != 7 {
		return "", fmt.Errorf("UID must be 7 bytes, got %d", len(uid))
	}
	if len(sdmFileKey) != 16 {
		return "", fmt.Errorf("SDM file key must be 16 bytes, got %d", len(sdmFileKey))
	}
	if counter > 0xFFFFFF {
		return "", fmt.Errorf("counter must be <= 0xFFFFFF, got %d", counter)
	}

	// Encode UID as uppercase hex (14 chars)
	uidHex := strings.ToUpper(hex.EncodeToString(uid))

	// Encode counter as 3-byte big-endian uppercase hex (6 chars)
	ctrBytesBE := []byte{
		byte((counter >> 16) & 0xFF),
		byte((counter >> 8) & 0xFF),
		byte(counter & 0xFF),
	}
	ctrHex := strings.ToUpper(hex.EncodeToString(ctrBytesBE))

	// Convert counter to little-endian for SDM key derivation
	ctrBytesLE := []byte{ctrBytesBE[2], ctrBytesBE[1], ctrBytesBE[0]}

	// Derive SDM session key
	sessionKey, err := DeriveSDMSessionKey(sdmFileKey, uid, ctrBytesLE)
	if err != nil {
		return "", fmt.Errorf("session key derive: %v", err)
	}

	// Build MAC input string
	macInput := fmt.Sprintf("uid=%s&ctr=%s&mac=", uidHex, ctrHex)

	// Compute CMAC
	cmac, err := aesCMAC(sessionKey, []byte(macInput))
	if err != nil {
		return "", fmt.Errorf("CMAC error: %v", err)
	}

	// Truncate to 8 bytes (odd bytes only)
	truncated := truncateOddBytes(cmac)
	macHex := strings.ToUpper(hex.EncodeToString(truncated))

	// Build final URL with query parameters
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid base URL: %v", err)
	}

	// Preserve existing query parameters and add SDM params
	q := parsedURL.Query()
	q.Set("uid", uidHex)
	q.Set("ctr", ctrHex)
	q.Set("mac", macHex)
	parsedURL.RawQuery = q.Encode()

	return parsedURL.String(), nil
}
