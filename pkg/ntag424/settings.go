package ntag424

import (
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// FileSettings represents the complete file settings structure.
// This is the full 16-field version from permissionsedit.
type FileSettings struct {
	FileType   byte   // 0x00 = standard data file
	FileOption byte   // bit 6 = SDM enabled, bits 1:0 = comm mode
	AR1        byte   // [ReadWrite nibble | ChangeAccessRights nibble]
	AR2        byte   // [Read nibble | Write nibble]
	Size       int    // File size in bytes (3-byte LE)
	SDMOptions byte   // SDM options (bit 7=UID, bit 6=Ctr, bit 0=TT)
	SDMMeta    byte   // Meta access rights (upper nibble of SDMAR)
	SDMFile    byte   // File access rights (bits 11:8 of SDMAR)
	SDMCtr     byte   // Counter access rights (lower nibble of SDMAR)
	RawData    []byte // Store raw response for debugging

	// Conditional SDM offset fields (present depending on SDMOptions/SDMAR)
	UIDOffset      uint32 // UID mirror offset (if bit7=1 and Meta=0xE)
	CtrOffset      uint32 // Counter mirror offset (if bit6=1 and Meta=0xE)
	MACInputOffset uint32 // MAC input offset (if File != 0xF)
	MACOffset      uint32 // MAC offset (if File != 0xF)
	ENCOffset      uint32 // ENC offset (if bit4=1)
	ENCLength      uint32 // ENC length (if bit4=1)
	CtrLimit       uint32 // Counter limit (if bit5=1)
}

// ParseFileSettings parses the raw GetFileSettings response.
// This is the most complete version from permissionsedit/main.go:546-629.
func ParseFileSettings(data []byte) (*FileSettings, error) {
	if len(data) < 7 {
		return nil, errors.New("file settings too short")
	}
	fs := &FileSettings{}
	fs.FileType = data[0]
	fs.FileOption = data[1]
	fs.AR1 = data[2]
	fs.AR2 = data[3]
	fs.Size = int(data[4]) | int(data[5])<<8 | int(data[6])<<16
	fs.RawData = make([]byte, len(data))
	copy(fs.RawData, data)

	idx := 7
	// If SDM not enabled (bit 6 = 0), we're done
	if (fs.FileOption & 0x40) == 0 {
		return fs, nil
	}

	// Parse SDM fields
	if len(data) < idx+3 {
		return nil, errors.New("file settings missing SDM fields")
	}
	fs.SDMOptions = data[idx]
	sdmAR := uint16(data[idx+1]) | (uint16(data[idx+2]) << 8)
	fs.SDMMeta = byte((sdmAR >> 12) & 0x0F)
	fs.SDMFile = byte((sdmAR >> 8) & 0x0F)
	fs.SDMCtr = byte(sdmAR & 0x0F)
	idx += 3

	// Parse conditional offset fields (mirroring buildChangeFileSettingsData logic)

	// UIDOffset: present if UID mirror enabled (bit7) AND meta is plain (0xE)
	if (fs.SDMOptions&0x80) != 0 && fs.SDMMeta == 0x0E {
		if len(data) < idx+3 {
			return nil, errors.New("file settings missing UIDOffset")
		}
		fs.UIDOffset = readU24le(data, idx)
		idx += 3
	}

	// CtrOffset: present if ReadCtr mirror enabled (bit6) AND meta is plain (0xE)
	if (fs.SDMOptions&0x40) != 0 && fs.SDMMeta == 0x0E {
		if len(data) < idx+3 {
			return nil, errors.New("file settings missing CtrOffset")
		}
		fs.CtrOffset = readU24le(data, idx)
		idx += 3
	}

	// PICCDataOffset: present if meta is NOT plain (encrypted PICC data)
	if fs.SDMMeta != 0x0E && fs.SDMMeta != 0x0F {
		if len(data) < idx+3 {
			return nil, errors.New("file settings missing PICCDataOffset")
		}
		fs.UIDOffset = readU24le(data, idx) // Reuse UIDOffset field for PICC data
		idx += 3
	}

	// SDMMACInputOffset + SDMMACOffset: present if SDMFileRead is not Denied (0xF)
	if fs.SDMFile != 0x0F {
		if len(data) < idx+6 {
			return nil, errors.New("file settings missing MAC offsets")
		}
		fs.MACInputOffset = readU24le(data, idx)
		fs.MACOffset = readU24le(data, idx+3)
		idx += 6
	}

	// SDMENCOffset + SDMENCLength: present if encrypted file data enabled (bit4)
	if (fs.SDMOptions & 0x10) != 0 {
		if len(data) < idx+6 {
			return nil, errors.New("file settings missing ENC offsets")
		}
		fs.ENCOffset = readU24le(data, idx)
		fs.ENCLength = readU24le(data, idx+3)
		idx += 6
	}

	// SDMReadCtrLimit: present if ReadCtr limit enabled (bit5)
	if (fs.SDMOptions & 0x20) != 0 {
		if len(data) < idx+3 {
			return nil, errors.New("file settings missing CtrLimit")
		}
		fs.CtrLimit = readU24le(data, idx)
		idx += 3
	}

	return fs, nil
}

// readU24le reads a 3-byte little-endian uint32 at the given offset.
func readU24le(data []byte, offset int) uint32 {
	return uint32(data[offset]) | uint32(data[offset+1])<<8 | uint32(data[offset+2])<<16
}

// u24le converts a uint32 to a 3-byte little-endian slice.
func u24le(v uint32) []byte {
	return []byte{byte(v & 0xFF), byte((v >> 8) & 0xFF), byte((v >> 16) & 0xFF)}
}

// GetFileSettings retrieves file settings using plain-first-then-secure strategy.
// This is the canonical version from update/internal/ntag/settings.go:9-68.
// It tries multiple plain APDU formats first, then falls back to secure messaging with retry logic.
func GetFileSettings(card Card, sess *Session, fileNo byte) (*FileSettings, error) {
	// Try multiple plain APDU formats
	plainFormats := [][]byte{
		{0x90, 0xF5, 0x00, 0x00, 0x01, fileNo, 0x20}, // Le=0x20 (32 bytes)
		{0x90, 0xF5, 0x00, 0x00, 0x01, fileNo, 0x10}, // Le=0x10 (16 bytes)
		{0x90, 0xF5, 0x00, 0x00, 0x01, fileNo},       // No Le
		{0x90, 0xF5, 0x00, 0x00, 0x01, fileNo, 0x00}, // Le=0x00 (256 bytes)
	}

	var plainSW uint16
	for i, apdu := range plainFormats {
		resp, sw, err := Transmit(card, apdu)
		plainSW = sw
		leStr := "none"
		if len(apdu) > 6 {
			leStr = fmt.Sprintf("0x%02X", apdu[len(apdu)-1])
		}
		slog.Debug("GetFileSettings plain attempt",
			"file_no", fmt.Sprintf("%02X", fileNo),
			"attempt", i+1,
			"le", leStr,
			"sw", fmt.Sprintf("%04X", sw),
			"resp_len", len(resp))
		if err == nil && (sw == SWSuccess || sw == SWDESFireOK) {
			slog.Debug("GetFileSettings plain success",
				"ar1", fmt.Sprintf("%02X", resp[2]),
				"ar2", fmt.Sprintf("%02X", resp[3]))
			return ParseFileSettings(resp)
		}
	}

	// Plain failed, try secure messaging
	slog.Warn("GetFileSettings fallback to secure",
		"reason", "all plain attempts failed",
		"last_sw", fmt.Sprintf("%04X", plainSW))

	// Try secure messaging with retry logic (tag may need time after ChangeFileSettings)
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			slog.Debug("GetFileSettings secure retry", "attempt", attempt, "delay_ms", 100)
			time.Sleep(100 * time.Millisecond)
		}

		out, err := SsmCmdFull(card, sess, 0xF5, []byte{fileNo}, nil)
		if err == nil {
			return ParseFileSettings(out)
		}
		lastErr = err

		// If it's not a length error, don't retry
		if !IsLengthError(lastErr) {
			break
		}
	}

	return nil, fmt.Errorf("plain SW=%04X; secure err: %v", plainSW, lastErr)
}

// GetFileSettingsPlain retrieves file settings using plain APDU (from ro/auth.go:212).
func GetFileSettingsPlain(card Card, fileNo byte) (*FileSettings, error) {
	apdu := []byte{0x90, 0xF5, 0x00, 0x00, 0x01, fileNo, 0x00}
	resp, sw, err := Transmit(card, apdu)
	if err != nil {
		return nil, err
	}
	if !SwOK(sw) {
		return nil, &SWError{Cmd: 0xF5, SW: sw}
	}
	return ParseFileSettings(resp)
}

// GetFileSettingsSecure retrieves file settings using secure messaging (from ro/auth.go:204).
func GetFileSettingsSecure(card Card, sess *Session, fileNo byte) (*FileSettings, error) {
	out, err := SsmCmdFull(card, sess, 0xF5, []byte{fileNo}, nil)
	if err != nil {
		return nil, err
	}
	return ParseFileSettings(out)
}

// ChangeFileSettingsBasic modifies file settings without SDM configuration.
// From update/internal/ntag/settings.go:103-108.
func ChangeFileSettingsBasic(card Card, sess *Session, fileNo byte, fileOption, ar1, ar2 byte) error {
	data := []byte{fileOption, ar1, ar2}
	_, err := SsmCmdFull(card, sess, 0x5F, []byte{fileNo}, data)
	return err
}

// ChangeFileSettingsSDM modifies file settings with SDM configuration.
// From update/internal/ntag/settings.go:110-118.
func ChangeFileSettingsSDM(card Card, sess *Session, fileNo byte, commMode byte, ar1, ar2 byte,
	sdmOptions, sdmMeta, sdmFile, sdmCtr byte,
	uidOffset, ctrOffset, macInputOffset, macOffset uint32) error {

	data := BuildChangeFileSettingsData(commMode, ar1, ar2, sdmOptions, sdmMeta, sdmFile, sdmCtr,
		uidOffset, ctrOffset, macInputOffset, macOffset)
	_, err := SsmCmdFull(card, sess, 0x5F, []byte{fileNo}, data)
	return err
}

// BuildChangeFileSettingsData constructs the ChangeFileSettings data payload.
// From update/internal/ntag/settings.go:120-145.
func BuildChangeFileSettingsData(commMode, ar1, ar2, sdmOptions, sdmMeta, sdmFile, sdmCtr byte,
	uidOffset, ctrOffset, macInputOffset, macOffset uint32) []byte {

	data := make([]byte, 0, 64)
	fileOption := (commMode & 0x03)
	if sdmOptions != 0x00 {
		fileOption |= 0x40 // Enable SDM only if SDMOptions is non-zero
	}
	data = append(data, fileOption, ar1, ar2, sdmOptions)

	// SDMAR: [Meta(15:12) | File(11:8) | RFU(7:4) | Ctr(3:0)]
	sdmAR := uint16((uint16(sdmMeta&0x0F) << 12) | (uint16(sdmFile&0x0F) << 8) | (0x0F << 4) | uint16(sdmCtr&0x0F))
	data = append(data, byte(sdmAR&0xFF), byte((sdmAR>>8)&0xFF))

	// Conditional offsets (must match tag's encoding rules)
	if (sdmOptions&0x80) != 0 && sdmMeta == 0x0E {
		data = append(data, u24le(uidOffset)...)
	}
	if (sdmOptions&0x40) != 0 && sdmMeta == 0x0E {
		data = append(data, u24le(ctrOffset)...)
	}
	if sdmFile != 0x0F {
		data = append(data, u24le(macInputOffset)...)
		data = append(data, u24le(macOffset)...)
	}

	return data
}
