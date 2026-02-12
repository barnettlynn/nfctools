package ntag424

import "fmt"

// TagVersion holds the hardware and software version information from GetVersion.
// From ro/card.go:10-30.
type TagVersion struct {
	HWVendorID    byte   // Hardware vendor ID
	HWType        byte   // Hardware type
	HWSubType     byte   // Hardware subtype
	HWMajorVer    byte   // Hardware major version
	HWMinorVer    byte   // Hardware minor version
	HWStorageSize byte   // Hardware storage size
	HWProtocol    byte   // Hardware protocol
	SWVendorID    byte   // Software vendor ID
	SWType        byte   // Software type
	SWSubType     byte   // Software subtype
	SWMajorVer    byte   // Software major version
	SWMinorVer    byte   // Software minor version
	SWStorageSize byte   // Software storage size
	SWProtocol    byte   // Software protocol
	UID           []byte // 7-byte UID
	BatchNo       []byte // 5-byte batch number
	FabKey        byte   // Fabrication key
	ProdYear      byte   // Production year (BCD)
	ProdWeek      byte   // Production week (nibble)
}

// GetVersion retrieves the tag version information using DESFire GetVersion (INS 0x60).
// This is a three-part command exchange at PICC level.
// From ro/card.go:162-216.
//
// Returns:
//   - TagVersion struct with hardware info, software info, UID, batch, and production date
//   - Error if any part fails
func GetVersion(card Card) (*TagVersion, error) {
	// First part: 0x60
	apdu1 := []byte{0x90, 0x60, 0x00, 0x00, 0x00}
	resp1, sw, err := Transmit(card, apdu1)
	if err != nil {
		return nil, err
	}
	if sw != SWMoreData || len(resp1) != 7 {
		return nil, fmt.Errorf("GetVersion part 1 failed (SW=%04X len=%d)", sw, len(resp1))
	}

	// Second part: 0xAF (Additional Frame)
	apdu2 := []byte{0x90, 0xAF, 0x00, 0x00, 0x00}
	resp2, sw, err := Transmit(card, apdu2)
	if err != nil {
		return nil, err
	}
	if sw != SWMoreData || len(resp2) != 7 {
		return nil, fmt.Errorf("GetVersion part 2 failed (SW=%04X len=%d)", sw, len(resp2))
	}

	// Third part: 0xAF (Additional Frame)
	apdu3 := []byte{0x90, 0xAF, 0x00, 0x00, 0x00}
	resp3, sw, err := Transmit(card, apdu3)
	if err != nil {
		return nil, err
	}
	if !SwOK(sw) || len(resp3) != 14 {
		return nil, fmt.Errorf("GetVersion part 3 failed (SW=%04X len=%d)", sw, len(resp3))
	}

	v := &TagVersion{
		HWVendorID:    resp1[0],
		HWType:        resp1[1],
		HWSubType:     resp1[2],
		HWMajorVer:    resp1[3],
		HWMinorVer:    resp1[4],
		HWStorageSize: resp1[5],
		HWProtocol:    resp1[6],
		SWVendorID:    resp2[0],
		SWType:        resp2[1],
		SWSubType:     resp2[2],
		SWMajorVer:    resp2[3],
		SWMinorVer:    resp2[4],
		SWStorageSize: resp2[5],
		SWProtocol:    resp2[6],
		UID:           resp3[0:7],
		BatchNo:       resp3[7:12],
		FabKey:        resp3[12],
		ProdYear:      resp3[13] >> 4,
		ProdWeek:      resp3[13] & 0x0F,
	}
	return v, nil
}
