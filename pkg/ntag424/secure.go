package ntag424

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
)

// BuildSsmApdu constructs a secure messaging APDU for DESFire commands.
// It encrypts the command data, computes the MAC, and assembles the final APDU.
//
// Parameters:
//   - sess: Active authenticated session (must not be nil)
//   - cmd: DESFire command byte (e.g., 0xBD for ReadData, 0x5F for ChangeFileSettings)
//   - header: Unencrypted header data (e.g., file number) sent in cleartext after Lc
//   - data: Command-specific data to be encrypted
//
// Returns:
//   - apdu: Complete APDU ready to transmit
//   - macInput: MAC input bytes (for debugging)
//   - encData: Encrypted data (for debugging)
//   - mact: Truncated MAC (for debugging)
//   - err: Error if any
func BuildSsmApdu(sess *Session, cmd byte, header, data []byte) (apdu, macInput, encData, mact []byte, err error) {
	if sess == nil {
		return nil, nil, nil, nil, errors.New("session is nil")
	}

	// Generate IV for command encryption: ECB-encrypt(Kenc, A5 5A TI(4) CmdCtr(2) 00..00)
	ivcIn := make([]byte, 16)
	ivcIn[0] = 0xA5
	ivcIn[1] = 0x5A
	copy(ivcIn[2:6], sess.ti[:])
	ivcIn[6] = byte(sess.cmdCtr & 0xFF)
	ivcIn[7] = byte((sess.cmdCtr >> 8) & 0xFF)
	ivc, err := aesECBEncrypt(sess.kenc[:], ivcIn)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Encrypt command data (if any) with IV_C
	if len(data) > 0 {
		padded := padISO9797M2(data)
		encData, err = aesCBCEncrypt(sess.kenc[:], ivc, padded)
		if err != nil {
			return nil, nil, nil, nil, err
		}
	} else {
		encData = []byte{}
	}

	// Build MAC input: Cmd(1) CmdCtr(2) TI(4) Header EncData
	macInput = make([]byte, 0, len(header)+len(encData)+8)
	macInput = append(macInput, cmd)
	macInput = append(macInput, byte(sess.cmdCtr&0xFF), byte((sess.cmdCtr>>8)&0xFF))
	macInput = append(macInput, sess.ti[:]...)
	macInput = append(macInput, header...)
	macInput = append(macInput, encData...)

	cmac, err := aesCMAC(sess.kmac[:], macInput)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	mact = truncateOddBytes(cmac)

	// Assemble final APDU: 90 Cmd 00 00 Lc Header EncData MACT 00
	dataLen := len(header) + len(encData) + len(mact)
	if dataLen > 255 {
		return nil, nil, nil, nil, fmt.Errorf("APDU data too long")
	}

	apdu = make([]byte, 0, 6+dataLen)
	apdu = append(apdu, 0x90, cmd, 0x00, 0x00, byte(dataLen))
	apdu = append(apdu, header...)
	apdu = append(apdu, encData...)
	apdu = append(apdu, mact...)
	apdu = append(apdu, 0x00)
	return apdu, macInput, encData, mact, nil
}

// SsmCmdFull executes a secure messaging command and verifies the response.
// It handles encryption, MAC generation, transmission, response verification,
// and decryption.
//
// Parameters:
//   - card: Card interface for transmission
//   - sess: Active authenticated session (increments cmdCtr on success)
//   - cmd: DESFire command byte
//   - header: Unencrypted header data
//   - data: Command-specific data to be encrypted
//
// Returns:
//   - Decrypted response data (without padding)
//   - Error if command fails, MAC mismatch, or decryption error
func SsmCmdFull(card Card, sess *Session, cmd byte, header, data []byte) ([]byte, error) {
	if sess == nil {
		return nil, errors.New("session is nil")
	}

	apdu, macInput, encData, mact, err := BuildSsmApdu(sess, cmd, header, data)
	if err != nil {
		return nil, err
	}
	slog.Debug("secure messaging",
		"cmd", fmt.Sprintf("0x%02X", cmd),
		"apdu", strings.ToUpper(hex.EncodeToString(apdu)),
		"enc", strings.ToUpper(hex.EncodeToString(encData)),
		"mac_input", strings.ToUpper(hex.EncodeToString(macInput)),
		"mact", strings.ToUpper(hex.EncodeToString(mact)))

	resp, sw, err := Transmit(card, apdu)
	if err != nil {
		return nil, err
	}
	if sw != SWDESFireOK {
		return nil, &SWError{Cmd: cmd, SW: sw}
	}
	if len(resp) < 8 {
		return nil, fmt.Errorf("response too short (len=%d, SW=%04X)", len(resp), sw)
	}

	// Split response into encrypted data and MAC
	respEncLen := len(resp) - 8
	respEnc := resp[:respEncLen]
	respMac := resp[respEncLen:]

	// Generate IV for response decryption: ECB-encrypt(Kenc, 5A A5 TI(4) (CmdCtr+1)(2) 00..00)
	cmdCtr1 := sess.cmdCtr + 1
	ivrIn := make([]byte, 16)
	ivrIn[0] = 0x5A
	ivrIn[1] = 0xA5
	copy(ivrIn[2:6], sess.ti[:])
	ivrIn[6] = byte(cmdCtr1 & 0xFF)
	ivrIn[7] = byte((cmdCtr1 >> 8) & 0xFF)
	ivr, err := aesECBEncrypt(sess.kenc[:], ivrIn)
	if err != nil {
		return nil, err
	}

	// Verify response MAC: CMAC(Kmac, SW(1) CmdCtr+1(2) TI(4) RespEnc)
	macIn2 := make([]byte, 0, 8+respEncLen)
	macIn2 = append(macIn2, byte(sw&0xFF))
	macIn2 = append(macIn2, byte(cmdCtr1&0xFF), byte((cmdCtr1>>8)&0xFF))
	macIn2 = append(macIn2, sess.ti[:]...)
	macIn2 = append(macIn2, respEnc...)

	cmac2, err := aesCMAC(sess.kmac[:], macIn2)
	if err != nil {
		return nil, err
	}
	mact2 := truncateOddBytes(cmac2)
	if !bytes.Equal(respMac, mact2) {
		return nil, errors.New("response MAC mismatch")
	}

	// Decrypt response data (if any) and remove padding
	out := []byte{}
	if respEncLen > 0 {
		dec, err := aesCBCDecrypt(sess.kenc[:], ivr, respEnc)
		if err != nil {
			return nil, err
		}
		out, err = unpadISO9797M2(dec)
		if err != nil {
			return nil, err
		}
	}

	sess.cmdCtr = cmdCtr1
	return out, nil
}
