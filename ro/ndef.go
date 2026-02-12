package main

import (
	"fmt"
)

func decodeNDEFURI(ndef []byte) (string, error) {
	if len(ndef) < 5 {
		return "", fmt.Errorf("NDEF too short")
	}
	hdr := ndef[0]
	sr := (hdr & 0x10) != 0
	il := (hdr & 0x08) != 0

	typeLen := int(ndef[1])
	idx := 2

	var payloadLen int
	if sr {
		payloadLen = int(ndef[idx])
		idx++
	} else {
		if len(ndef) < idx+4 {
			return "", fmt.Errorf("NDEF too short for payload length")
		}
		payloadLen = int(ndef[idx])<<24 | int(ndef[idx+1])<<16 | int(ndef[idx+2])<<8 | int(ndef[idx+3])
		idx += 4
	}

	idLen := 0
	if il {
		idLen = int(ndef[idx])
		idx++
	}

	if len(ndef) < idx+typeLen+idLen+payloadLen {
		return "", fmt.Errorf("NDEF record truncated")
	}

	recType := ndef[idx : idx+typeLen]
	idx += typeLen

	if string(recType) != "U" {
		return "", fmt.Errorf("not a URI record")
	}

	idx += idLen
	payload := ndef[idx : idx+payloadLen]
	if len(payload) == 0 {
		return "", fmt.Errorf("empty URI payload")
	}

	uriPrefix := []string{
		"", "http://www.", "https://www.", "http://", "https://",
		"tel:", "mailto:", "ftp://anonymous:anonymous@", "ftp://ftp.",
		"ftps://", "sftp://", "smb://", "nfs://", "ftp://", "dav://",
		"news:", "telnet://", "imap:", "rtsp://", "urn:", "pop:",
		"sip:", "sips:", "tftp:", "btspp://", "btl2cap://",
		"btgoep://", "tcpobex://", "irdaobex://", "file://",
		"urn:epc:id:", "urn:epc:tag:", "urn:epc:pat:",
		"urn:epc:raw:", "urn:epc:", "urn:nfc:",
	}

	prefix := ""
	code := int(payload[0])
	if code < len(uriPrefix) {
		prefix = uriPrefix[code]
	}
	return prefix + string(payload[1:]), nil
}

func printNDEFInfo(ndef []byte) {
	if len(ndef) < 3 {
		return
	}
	hdr := ndef[0]
	sr := (hdr & 0x10) != 0
	il := (hdr & 0x08) != 0
	typeLen := int(ndef[1])
	idx := 2

	payloadLenBytes := []byte{}
	if sr {
		if len(ndef) < idx+1 {
			return
		}
		payloadLenBytes = ndef[idx : idx+1]
		idx++
	} else {
		if len(ndef) < idx+4 {
			return
		}
		payloadLenBytes = ndef[idx : idx+4]
		idx += 4
	}

	if il {
		if len(ndef) < idx+1 {
			return
		}
		idx++
	}

	if len(ndef) < idx+typeLen {
		return
	}
	recType := ndef[idx : idx+typeLen]

	fmt.Println("NDEF record:")
	fmt.Printf("  - %02X = NDEF header (MB=%d, ME=%d, SR=%d, IL=%d, TNF=0x%X)\n",
		hdr,
		boolToInt(hdr&0x80 != 0),
		boolToInt(hdr&0x40 != 0),
		boolToInt(hdr&0x10 != 0),
		boolToInt(hdr&0x08 != 0),
		hdr&0x07)
	fmt.Printf("  - %02X = type length\n", ndef[1])
	if sr {
		fmt.Printf("  - %02X = payload length\n", payloadLenBytes[0])
	} else {
		fmt.Printf("  - %s = payload length\n", hexUpper(payloadLenBytes))
	}
	if len(recType) == 1 && recType[0] == 'U' {
		fmt.Printf("  - %02X = type U (URI record)\n", recType[0])
	} else {
		fmt.Printf("  - %s = type (%q)\n", hexUpper(recType), string(recType))
	}
}
