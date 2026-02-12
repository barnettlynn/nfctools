package ntag424

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// KeyFile represents a key loaded from a .hex file.
type KeyFile struct {
	Name string // File name (e.g., "key0.hex")
	Key  []byte // 16-byte AES key
}

// CRC32DESFire computes the CRC32 of data using the DESFire polynomial (0xEDB88320).
// Used for key versioning in ChangeKey operations.
// From update/internal/ntag/keys.go:13-27.
func CRC32DESFire(data []byte) uint32 {
	poly := uint32(0xEDB88320)
	crc := uint32(0xFFFFFFFF)
	for _, b := range data {
		crc ^= uint32(b)
		for i := 0; i < 8; i++ {
			if (crc & 1) != 0 {
				crc = (crc >> 1) ^ poly
			} else {
				crc = crc >> 1
			}
		}
	}
	return crc
}

// LoadKeyHexFile loads a 16-byte AES key from a .hex file.
// The file should contain a single line with 32 hexadecimal characters.
// From update/internal/ntag/keys.go:101-127.
func LoadKeyHexFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if len(line) != 32 {
			return nil, fmt.Errorf("key must be 32 hex chars, got %d", len(line))
		}
		key, err := hex.DecodeString(line)
		if err != nil {
			return nil, fmt.Errorf("invalid hex key: %v", err)
		}
		return key, nil
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("key file is empty")
}

// LoadAllHexKeys loads all .hex key files from a directory.
// Returns a slice of KeyFile structs with name and key data.
// Skips invalid files silently.
// From ro/keyfile.go:90-118.
func LoadAllHexKeys(dir string) ([]KeyFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var keys []KeyFile
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.ToLower(filepath.Ext(e.Name())) != ".hex" {
			continue
		}

		path := filepath.Join(dir, e.Name())
		key, err := LoadKeyHexFile(path)
		if err != nil {
			continue // Skip invalid key files
		}

		keys = append(keys, KeyFile{
			Name: e.Name(),
			Key:  key,
		})
	}

	return keys, nil
}

// ChangeKey changes a key slot using DESFire ChangeKey (INS 0xC4) with cross-slot support.
// This is the canonical version from keyswap/main.go:487-520.
//
// Parameters:
//   - card: Card interface
//   - sess: Active authenticated session
//   - keySlot: Slot to change (0-15)
//   - newKey: New 16-byte AES key
//   - oldKey: Old 16-byte AES key (for XOR and CRC)
//   - keyVersion: Key version byte (0x00 for no versioning)
//   - authSlot: Slot used for authentication
//
// Key data format:
//   - If changing same slot (keySlot == authSlot): XOR(16) + version(1) + CRC_new(4) + CRC_old(4) = 25 bytes
//   - If changing different slot: XOR(16) + version(1) + CRC_new(4) = 21 bytes
//
// Note: For same-slot changes, prefer ChangeKeySame which handles session invalidation correctly.
func ChangeKey(card Card, sess *Session, keySlot byte, newKey, oldKey []byte, keyVersion byte, authSlot byte) error {
	changingSameKey := (keySlot == authSlot)

	var keyData []byte
	if changingSameKey {
		keyData = make([]byte, 25) // XOR + version + CRC_new + CRC_old
	} else {
		keyData = make([]byte, 21) // XOR + version + CRC_new
	}

	// XOR new and old keys
	for i := 0; i < 16; i++ {
		keyData[i] = newKey[i] ^ oldKey[i]
	}
	keyData[16] = keyVersion

	// CRC of new key
	crcNew := CRC32DESFire(newKey)
	keyData[17] = byte(crcNew & 0xFF)
	keyData[18] = byte((crcNew >> 8) & 0xFF)
	keyData[19] = byte((crcNew >> 16) & 0xFF)
	keyData[20] = byte((crcNew >> 24) & 0xFF)

	// CRC of old key (only if changing same slot)
	if changingSameKey {
		crcOld := CRC32DESFire(oldKey)
		keyData[21] = byte(crcOld & 0xFF)
		keyData[22] = byte((crcOld >> 8) & 0xFF)
		keyData[23] = byte((crcOld >> 16) & 0xFF)
		keyData[24] = byte((crcOld >> 24) & 0xFF)
	}

	_, err := SsmCmdFull(card, sess, 0xC4, []byte{keySlot}, keyData)
	return err
}

// ChangeKeySame changes the same key slot used for authentication.
// This is the canonical version from keyswap/main.go:522-595.
//
// IMPORTANT: This operation INVALIDATES the authentication session.
// The response has NO CMAC (status-only response).
//
// Parameters:
//   - card: Card interface
//   - sess: Active authenticated session (will be invalidated)
//   - keySlot: Slot to change (must match authenticated slot)
//   - newKey: New 16-byte AES key
//   - keyVersion: Key version byte (0x00 for no versioning)
//
// Key data format:
//   - NewKey(16) + KeyVersion(1) — no XOR, no CRC
//
// This function manually builds the secure messaging APDU because the response
// format is different (no CMAC).
func ChangeKeySame(card Card, sess *Session, keySlot byte, newKey []byte, keyVersion byte) error {
	if sess == nil {
		return errors.New("session is nil")
	}

	// Build keyData: NewKey(16) + KeyVersion(1) — no XOR, no CRC
	keyData := make([]byte, 17)
	copy(keyData, newKey)
	keyData[16] = keyVersion

	// Pad to 32 bytes
	padded := padISO9797M2(keyData)

	// Build IVC (same as SsmCmdFull)
	ivcIn := make([]byte, 16)
	ivcIn[0] = 0xA5
	ivcIn[1] = 0x5A
	copy(ivcIn[2:6], sess.ti[:])
	ivcIn[6] = byte(sess.cmdCtr & 0xFF)
	ivcIn[7] = byte((sess.cmdCtr >> 8) & 0xFF)
	ivc, err := aesECBEncrypt(sess.kenc[:], ivcIn)
	if err != nil {
		return err
	}

	// Encrypt keyData
	encData, err := aesCBCEncrypt(sess.kenc[:], ivc, padded)
	if err != nil {
		return err
	}

	// Build MAC input: cmd(1) + cmdCtr(2) + TI(4) + header(1) + encData(32)
	header := []byte{keySlot}
	macInput := make([]byte, 0, 1+2+4+len(header)+len(encData))
	macInput = append(macInput, 0xC4) // ChangeKey command
	macInput = append(macInput, byte(sess.cmdCtr&0xFF), byte((sess.cmdCtr>>8)&0xFF))
	macInput = append(macInput, sess.ti[:]...)
	macInput = append(macInput, header...)
	macInput = append(macInput, encData...)

	// Compute CMAC
	cmac, err := aesCMAC(sess.kmac[:], macInput)
	if err != nil {
		return err
	}
	mact := truncateOddBytes(cmac)

	// Build APDU
	dataLen := len(header) + len(encData) + len(mact)
	if dataLen > 255 {
		return fmt.Errorf("APDU data too long")
	}
	apdu := make([]byte, 0, 6+dataLen)
	apdu = append(apdu, 0x90, 0xC4, 0x00, 0x00, byte(dataLen))
	apdu = append(apdu, header...)
	apdu = append(apdu, encData...)
	apdu = append(apdu, mact...)
	apdu = append(apdu, 0x00)

	// Transmit and check SW only (no response CMAC validation)
	_, sw, err := Transmit(card, apdu)
	if err != nil {
		return err
	}
	if sw != SWDESFireOK {
		return &SWError{Cmd: 0xC4, SW: sw}
	}

	// Session is now invalidated, don't increment cmdCtr
	return nil
}

// SessionFromEnv creates a Session from environment variables (for testing/debugging).
// Environment variables:
//   - NTAG_KENC: 32-character hex string (16 bytes)
//   - NTAG_KMAC: 32-character hex string (16 bytes)
//   - NTAG_TI: 8-character hex string (4 bytes)
//   - NTAG_CMDC: Optional hex command counter
//
// From update/internal/ntag/keys.go:62-99.
func SessionFromEnv() (*Session, error) {
	kencHex := strings.TrimSpace(os.Getenv("NTAG_KENC"))
	kmacHex := strings.TrimSpace(os.Getenv("NTAG_KMAC"))
	tiHex := strings.TrimSpace(os.Getenv("NTAG_TI"))
	cmdcHex := strings.TrimSpace(os.Getenv("NTAG_CMDC"))

	if len(kencHex) != 32 || len(kmacHex) != 32 || len(tiHex) != 8 {
		return nil, fmt.Errorf("NTAG_KENC/NTAG_KMAC must be 32 hex and NTAG_TI must be 8 hex")
	}

	kenc, err := hex.DecodeString(kencHex)
	if err != nil {
		return nil, fmt.Errorf("NTAG_KENC invalid hex: %v", err)
	}
	kmac, err := hex.DecodeString(kmacHex)
	if err != nil {
		return nil, fmt.Errorf("NTAG_KMAC invalid hex: %v", err)
	}
	ti, err := hex.DecodeString(tiHex)
	if err != nil {
		return nil, fmt.Errorf("NTAG_TI invalid hex: %v", err)
	}

	s := &Session{}
	copy(s.kenc[:], kenc)
	copy(s.kmac[:], kmac)
	copy(s.ti[:], ti)
	s.cmdCtr = 0

	if cmdcHex != "" {
		cmdc, err := strconv.ParseUint(cmdcHex, 16, 16)
		if err != nil {
			return nil, fmt.Errorf("NTAG_CMDC invalid hex: %v", err)
		}
		s.cmdCtr = uint16(cmdc)
	}
	return s, nil
}
