package ntag424

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"
)

const (
	sdmUIDLenASCII = 14
	sdmCtrLenASCII = 6
	sdmMacLenASCII = 16
)

// SDMNDEF represents an NDEF message with SDM (Secure Dynamic Messaging) parameters.
type SDMNDEF struct {
	URL            string // Full URL with uid/ctr/mac placeholders
	NDEF           []byte // Complete NDEF message bytes
	UIDOffset      uint32 // Byte offset where UID mirror starts
	CtrOffset      uint32 // Byte offset where counter mirror starts
	MacInputOffset uint32 // Byte offset where MAC input starts (typically "uid=")
	MacOffset      uint32 // Byte offset where MAC mirror starts
}

// BuildSDMNDEF constructs an NDEF message with SDM placeholders from a base URL.
// From update/internal/ntag/ndef.go:10-99.
//
// The function:
//   1. Parses and validates the URL
//   2. Adds uid, ctr, mac query parameters with zero-filled placeholders
//   3. Builds an NDEF URI record with proper prefix encoding
//   4. Calculates byte offsets for SDM mirroring
//
// Parameters:
//   - baseURL: Base URL (must be absolute with scheme and host)
//
// Returns:
//   - SDMNDEF structure with URL, NDEF bytes, and mirror offsets
//   - Error if URL is invalid or NDEF exceeds 256 bytes
//
// Example:
//   BuildSDMNDEF("https://example.com/tag")
//   → URL: "https://example.com/tag?uid=00000000000000&ctr=000000&mac=0000000000000000"
//   → UIDOffset: offset to first '0' after "uid="
//   → CtrOffset: offset to first '0' after "ctr="
//   → MacOffset: offset to first '0' after "mac="
func BuildSDMNDEF(baseURL string) (*SDMNDEF, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("URL must be absolute (include scheme and host)")
	}
	parsed.Fragment = ""

	// Build query string manually to preserve uid, ctr, mac order
	// (url.Values.Encode() sorts alphabetically, violating NTAG 424 DNA ordering constraint)
	query := parsed.Query()
	var params []string
	// Add SDM parameters in required order: uid, ctr, mac
	params = append(params, fmt.Sprintf("uid=%s", url.QueryEscape(strings.Repeat("0", sdmUIDLenASCII))))
	params = append(params, fmt.Sprintf("ctr=%s", url.QueryEscape(strings.Repeat("0", sdmCtrLenASCII))))
	params = append(params, fmt.Sprintf("mac=%s", url.QueryEscape(strings.Repeat("0", sdmMacLenASCII))))
	// Preserve any other existing query parameters
	for key, values := range query {
		if key != "uid" && key != "ctr" && key != "mac" {
			for _, value := range values {
				params = append(params, fmt.Sprintf("%s=%s", url.QueryEscape(key), url.QueryEscape(value)))
			}
		}
	}
	parsed.RawQuery = strings.Join(params, "&")

	fullURL := parsed.String()

	// Encode URL prefix according to NFC URI Record Type Definition
	prefixCode := byte(0x00)
	uri := fullURL
	for _, p := range []struct {
		prefix string
		code   byte
	}{
		{prefix: "https://www.", code: 0x02},
		{prefix: "http://www.", code: 0x01},
		{prefix: "https://", code: 0x04},
		{prefix: "http://", code: 0x03},
	} {
		if strings.HasPrefix(fullURL, p.prefix) {
			prefixCode = p.code
			uri = fullURL[len(p.prefix):]
			break
		}
	}

	// Build NDEF message: NLEN(2) + NDEF Record
	// NDEF Record: TNFFLAGS(1) TYPELEN(1) PAYLOADLEN(1) TYPE(1) PAYLOAD
	payloadLen := 1 + len(uri) // prefix code + URI
	if payloadLen > 255 {
		return nil, fmt.Errorf("URI too long")
	}
	recordLen := 4 + payloadLen // header(3) + type(1) + payload
	totalLen := 2 + recordLen   // NLEN(2) + record
	if totalLen > 256 {
		return nil, fmt.Errorf("NDEF too long")
	}

	ndef := make([]byte, totalLen)
	ndef[0] = byte((recordLen >> 8) & 0xFF) // NLEN high byte
	ndef[1] = byte(recordLen & 0xFF)        // NLEN low byte
	ndef[2] = 0xD1                          // TNF=0x01 (Well-known), MB=1, ME=1, SR=1
	ndef[3] = 0x01                          // Type length = 1
	ndef[4] = byte(payloadLen)              // Payload length
	ndef[5] = 0x55                          // Type 'U' (URI)
	ndef[6] = prefixCode                    // URI prefix code
	copy(ndef[7:], []byte(uri))             // URI (without prefix)

	// Locate SDM parameter positions in the NDEF message
	uidIdx := bytes.Index(ndef, []byte("uid="))
	ctrIdx := bytes.Index(ndef, []byte("ctr="))
	macIdx := bytes.Index(ndef, []byte("mac="))
	if uidIdx < 0 || ctrIdx < 0 || macIdx < 0 {
		return nil, fmt.Errorf("failed to locate uid/ctr/mac in NDEF")
	}

	// Offsets point to the first placeholder character after "uid=", "ctr=", "mac="
	uidOffset := uidIdx + 4
	ctrOffset := ctrIdx + 4
	macOffset := macIdx + 4
	if uidOffset+sdmUIDLenASCII > len(ndef) || ctrOffset+sdmCtrLenASCII > len(ndef) || macOffset+sdmMacLenASCII > len(ndef) {
		return nil, fmt.Errorf("offsets out of range")
	}

	return &SDMNDEF{
		URL:            fullURL,
		NDEF:           ndef,
		UIDOffset:      uint32(uidOffset),
		CtrOffset:      uint32(ctrOffset),
		MacInputOffset: uint32(uidIdx), // MAC input starts at "uid="
		MacOffset:      uint32(macOffset),
	}, nil
}
