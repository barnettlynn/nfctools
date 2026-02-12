package ntag424

import (
	"fmt"
	"log/slog"
	"strings"
)

// ReadBinary reads data from the currently selected file using ISO 7816 READ BINARY (INS 0xB0).
// Automatically retries with correct Le if the tag returns SW=6C00 (wrong Le).
// This is the canonical version from ro/card.go:86-103.
//
// Parameters:
//   - card: Card interface for transmission
//   - offset: 16-bit offset (encoded in P1P2)
//   - le: Expected length (0x00 = wildcard up to 256 bytes)
//
// Returns:
//   - Data read from the file
//   - Error if read fails
//
// Note: READ BINARY CANNOT use DESFire secure messaging. If the file requires
// authentication (Read != free), use ReadFileDataSecure instead.
func ReadBinary(card Card, offset uint16, le byte) ([]byte, error) {
	apdu := []byte{0x00, 0xB0, byte(offset >> 8), byte(offset), le}
	data, sw, err := Transmit(card, apdu)
	if err != nil {
		return nil, err
	}

	// If wrong Le (SW=6C00), retry with correct Le from SW2
	if (sw & 0xFF00) == SWWrongLe {
		correctLe := byte(sw & 0x00FF)
		slog.Warn("wrong Le, retrying", "original_le", apdu[4], "correct_le", correctLe)
		apdu[4] = correctLe
		data, sw, err = Transmit(card, apdu)
		if err != nil {
			return nil, err
		}
	}

	if !SwOK(sw) {
		return nil, &SWError{Cmd: 0xB0, SW: sw}
	}
	return data, nil
}

// ReadNDEF reads the complete NDEF message from File 2 using ISO READ BINARY.
// This is the canonical version from ro/card.go:105-160.
//
// Steps:
//   1. Select NDEF application (AID D2760000850101)
//   2. Select CC file (0xE103) and read to get NDEF file ID
//   3. Select NDEF file (typically 0xE104)
//   4. Read NLEN (2-byte big-endian length header)
//   5. Read NDEF message in 255-byte chunks
//
// Returns:
//   - Complete NDEF message (without NLEN header)
//   - Error if any step fails
func ReadNDEF(card Card) ([]byte, error) {
	if err := SelectNDEFApp(card); err != nil {
		return nil, err
	}

	// Select CC file to determine NDEF file ID
	if err := SelectFile(card, 0xE103); err != nil {
		return nil, err
	}
	cc, err := ReadBinary(card, 0x0000, 0x0F)
	if err != nil {
		return nil, err
	}
	if len(cc) < 15 {
		return nil, fmt.Errorf("CC file too short")
	}

	// Extract NDEF file ID from CC (default 0xE104)
	ndefFileID := uint16(0xE104)
	if cc[7] == 0x04 && cc[8] >= 6 {
		ndefFileID = uint16(cc[9])<<8 | uint16(cc[10])
	}

	// Select NDEF file
	if err := SelectFile(card, ndefFileID); err != nil {
		return nil, err
	}

	// Read NLEN (2-byte big-endian length)
	nlenBytes, err := ReadBinary(card, 0x0000, 0x02)
	if err != nil {
		return nil, err
	}
	if len(nlenBytes) < 2 {
		return nil, fmt.Errorf("NLEN read too short")
	}
	nlen := int(nlenBytes[0])<<8 | int(nlenBytes[1])
	if nlen == 0 {
		return []byte{}, nil
	}

	// Read NDEF message in chunks (max 255 bytes per READ BINARY)
	ndef := make([]byte, 0, nlen)
	offset := 2 // Skip NLEN header
	remaining := nlen
	for remaining > 0 {
		chunk := remaining
		if chunk > 0xFF {
			chunk = 0xFF
		}
		part, err := ReadBinary(card, uint16(offset), byte(chunk))
		if err != nil {
			return nil, err
		}
		if len(part) == 0 {
			break
		}
		ndef = append(ndef, part...)
		offset += len(part)
		remaining -= len(part)
	}
	return ndef, nil
}

// ReadFileDataPlain reads file data using DESFire native ReadData (INS 0xBD) without authentication.
// This is from ro/card.go:718-745.
//
// Parameters:
//   - card: Card interface
//   - fileNo: File number (0x01, 0x02, 0x03)
//   - offset: Byte offset within file
//   - length: Number of bytes to read
//
// Returns:
//   - Data read from file
//   - Error if read fails
//
// Fail states:
//   - SW=6982: Authentication required (Read != free)
//   - SW=911C: Boundary error (offset+length > file size)
func ReadFileDataPlain(card Card, fileNo byte, offset, length int) ([]byte, error) {
	apdu := []byte{0x90, 0xBD, 0x00, 0x00, 0x07,
		fileNo,
		byte(offset), byte(offset >> 8), byte(offset >> 16),
		byte(length), byte(length >> 8), byte(length >> 16),
		0x00}
	data, sw, err := Transmit(card, apdu)
	if err != nil {
		return nil, err
	}
	if !SwOK(sw) {
		return nil, &SWError{Cmd: 0xBD, SW: sw}
	}
	return data, nil
}

// ReadFileDataSecure reads file data using DESFire native ReadData (INS 0xBD) with secure messaging.
// This is from ro/card.go:794-815.
//
// Parameters:
//   - card: Card interface
//   - sess: Active authenticated session
//   - fileNo: File number (0x01, 0x02, 0x03)
//   - offset: Byte offset within file
//   - length: Number of bytes to read
//   - debug: Enable debug output
//
// Returns:
//   - Data read from file
//   - Error if read fails
//
// Fail states:
//   - SW=911C: Boundary error (offset+length > file size). Treat as empty file.
//   - Response MAC mismatch: Session corrupted. Re-authenticate.
func ReadFileDataSecure(card Card, sess *Session, fileNo byte, offset, length int) ([]byte, error) {
	cmdData := []byte{
		fileNo,
		byte(offset), byte(offset >> 8), byte(offset >> 16),
		byte(length), byte(length >> 8), byte(length >> 16),
	}
	data, err := SsmCmdFull(card, sess, 0xBD, nil, cmdData)
	if err != nil {
		// Check for boundary error (SW=911C) - file is empty or smaller than requested
		if strings.Contains(err.Error(), "SW=911C") || IsBoundaryError(err) {
			return []byte{}, nil
		}
		return nil, err
	}
	return data, nil
}

// ReadCCFile reads the Capability Container (CC) file (File 1, ID 0xE103).
// This is from ro/card.go:592-610.
//
// Returns:
//   - CC file contents (typically 15-32 bytes)
//   - Error if read fails
func ReadCCFile(card Card) ([]byte, error) {
	// Select NDEF application
	if err := SelectNDEFApp(card); err != nil {
		return nil, err
	}

	// Select file 0xE103 (CC / Capability Container)
	if err := SelectFile(card, 0xE103); err != nil {
		return nil, err
	}

	// Read CC file - typically 15-23 bytes, read up to 32 to be safe
	data, err := ReadBinary(card, 0x0000, 0x20)
	if err != nil {
		return nil, err
	}

	return data, nil
}
