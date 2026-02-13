package ntag424

import (
	"encoding/hex"
)

const (
	ndefFileID = 0xE104
	ndefAppAID = "D2760000850101"
)

// SelectNDEFApp selects the NFC Forum NDEF application (AID D2760000850101).
// From update/internal/ntag/io.go:60-72.
//
// CRITICAL: This INVALIDATES any active authentication session.
// Always select BEFORE authenticating, or re-authenticate after selecting.
func SelectNDEFApp(card Card) error {
	aid, _ := hex.DecodeString(ndefAppAID)
	apdu := append([]byte{0x00, 0xA4, 0x04, 0x00, byte(len(aid))}, aid...)
	apdu = append(apdu, 0x00)
	_, sw, err := Transmit(card, apdu)
	if err != nil {
		return err
	}
	if !SwOK(sw) {
		return &SWError{Cmd: 0xA4, SW: sw}
	}
	return nil
}

// SelectFile selects a file by its 16-bit ID using ISO 7816 SELECT FILE.
// From update/internal/ntag/io.go:74-84.
//
// Common file IDs:
//   - 0xE103: CC (Capability Container)
//   - 0xE104: NDEF file
//   - 0xE105: Proprietary data file
//
// CRITICAL: This INVALIDATES any active authentication session.
// Always select BEFORE authenticating, or re-authenticate after selecting.
func SelectFile(card Card, fileID uint16) error {
	apdu := []byte{0x00, 0xA4, 0x00, 0x0C, 0x02, byte(fileID >> 8), byte(fileID)}
	_, sw, err := Transmit(card, apdu)
	if err != nil {
		return err
	}
	if !SwOK(sw) {
		return &SWError{Cmd: 0xA4, SW: sw}
	}
	return nil
}

// WriteNDEFPlain writes NDEF data without authentication.
// Selects NDEF app and file, then writes data using ISO UPDATE BINARY.
// From update/internal/ntag/io.go:13-21.
func WriteNDEFPlain(card Card, data []byte) error {
	if err := SelectNDEFApp(card); err != nil {
		return err
	}
	if err := SelectFile(card, ndefFileID); err != nil {
		return err
	}
	return WriteNDEFData(card, data)
}

// WriteNDEFWithAuth writes NDEF data after authentication.
// Assumes NDEF app is already selected and authentication is active.
// Does NOT call SelectNDEFApp to preserve the auth session.
// From update/internal/ntag/io.go:23-31.
func WriteNDEFWithAuth(card Card, data []byte) error {
	if err := SelectFile(card, ndefFileID); err != nil {
		return err
	}
	return WriteNDEFData(card, data)
}

// WriteNDEFData writes NDEF data without selecting app/file.
// Caller must ensure NDEF app and file are already selected.
// Use this after authentication to avoid resetting the auth session.
// From update/internal/ntag/io.go:33-58.
//
// Writes data in chunks of up to 255 bytes using ISO UPDATE BINARY (INS 0xD6).
func WriteNDEFData(card Card, data []byte) error {
	offset := 0
	for offset < len(data) {
		chunk := len(data) - offset
		if chunk > 0xFF {
			chunk = 0xFF
		}

		apdu := make([]byte, 0, 5+chunk)
		apdu = append(apdu, 0x00, 0xD6, byte(offset>>8), byte(offset), byte(chunk))
		apdu = append(apdu, data[offset:offset+chunk]...)

		_, sw, err := Transmit(card, apdu)
		if err != nil {
			return err
		}
		if !SwOK(sw) {
			return &SWError{Cmd: 0xD6, SW: sw}
		}
		offset += chunk
	}
	return nil
}

// WriteFileDataPlain writes data to a file using DESFire native WriteData (INS 0x3D).
// This respects DESFire access rights (Write=free will work without authentication).
// Mirrors ReadFileDataPlain but for writing.
func WriteFileDataPlain(card Card, fileNo byte, offset int, data []byte) error {
	written := 0
	for written < len(data) {
		chunk := len(data) - written
		if chunk > 0xFF {
			chunk = 0xFF
		}

		apdu := make([]byte, 0, 12+chunk)
		apdu = append(apdu, 0x90, 0x3D, 0x00, 0x00, byte(7+chunk))
		apdu = append(apdu, fileNo)
		apdu = append(apdu, byte(offset), byte(offset>>8), byte(offset>>16))
		apdu = append(apdu, byte(chunk), byte(chunk>>8), byte(chunk>>16))
		apdu = append(apdu, data[written:written+chunk]...)
		apdu = append(apdu, 0x00)

		_, sw, err := Transmit(card, apdu)
		if err != nil {
			return err
		}
		if !SwOK(sw) {
			return &SWError{Cmd: 0x3D, SW: sw}
		}
		written += chunk
		offset += chunk
	}
	return nil
}

// WriteFileDataSecure writes data to a file using DESFire native WriteData (INS 0x3D)
// with secure messaging (CMAC). Requires active authentication session.
// Mirrors ReadFileDataSecure - all parameters go in encrypted cmdData.
func WriteFileDataSecure(card Card, sess *Session, fileNo byte, offset int, data []byte) error {
	written := 0
	for written < len(data) {
		chunk := len(data) - written
		// Use very small chunks to avoid APDU length issues
		if chunk > 16 {
			chunk = 16
		}

		// Build command data: fileNo + offset (3 LE) + length (3 LE) + file data
		// Everything gets encrypted together, just like ReadFileDataSecure
		cmdData := make([]byte, 0, 7+chunk)
		cmdData = append(cmdData, fileNo)
		cmdData = append(cmdData, byte(offset), byte(offset>>8), byte(offset>>16))
		cmdData = append(cmdData, byte(chunk), byte(chunk>>8), byte(chunk>>16))
		cmdData = append(cmdData, data[written:written+chunk]...)

		// Use SsmCmdFull with nil header (everything in encrypted data)
		_, err := SsmCmdFull(card, sess, 0x3D, nil, cmdData)
		if err != nil {
			return err
		}

		written += chunk
		offset += chunk
	}
	return nil
}
