package ntag424

import "fmt"

// Card abstracts card transmit behavior for real PC/SC cards and test doubles.
type Card interface {
	Transmit(apdu []byte) ([]byte, error)
}

// Transmit sends an APDU to the card and extracts the status word.
// Returns (response_data, status_word, error).
// The response data does NOT include the trailing SW bytes.
func Transmit(card Card, apdu []byte) ([]byte, uint16, error) {
	resp, err := card.Transmit(apdu)
	if err != nil {
		return nil, 0, err
	}
	if len(resp) < 2 {
		return nil, 0, fmt.Errorf("short response: %d bytes", len(resp))
	}
	sw := uint16(resp[len(resp)-2])<<8 | uint16(resp[len(resp)-1])
	return resp[:len(resp)-2], sw, nil
}

// GetUID retrieves the card UID via ISO 7816 GET DATA command (FF CA 00 00).
// Tries with Le=0x00 (wildcard) and Le=0x04 (specific 4-byte UID length).
func GetUID(card Card) ([]byte, error) {
	for _, le := range []byte{0x00, 0x04} {
		apdu := []byte{0xFF, 0xCA, 0x00, 0x00, le}
		data, sw, err := Transmit(card, apdu)
		if err == nil && SwOK(sw) && len(data) > 0 {
			return data, nil
		}
	}
	return nil, fmt.Errorf("UID not available via GET DATA")
}
