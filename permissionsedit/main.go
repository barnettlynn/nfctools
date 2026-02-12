package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/ebfe/scard"
	"golang.org/x/term"
)

// ============================================================================
// Types
// ============================================================================

type session struct {
	kenc   [16]byte
	kmac   [16]byte
	ti     [4]byte
	cmdCtr uint16
}

type keyFile struct {
	name string
	key  []byte
}

type probeResult struct {
	key   []byte
	label string
}

type fileSettings struct {
	fileType       byte
	fileOption     byte
	ar1            byte
	ar2            byte
	size           int
	sdmOptions     byte
	sdmMeta        byte
	sdmFile        byte
	sdmCtr         byte
	rawData        []byte // Store raw response for building ChangeFileSettings
	uidOffset      uint32
	ctrOffset      uint32
	macInputOffset uint32
	macOffset      uint32
	encOffset      uint32
	encLength      uint32
	ctrLimit       uint32
}

// ============================================================================
// Card I/O
// ============================================================================

func transmit(card *scard.Card, apdu []byte) ([]byte, uint16, error) {
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

func swOK(sw uint16) bool {
	return sw == 0x9000 || sw == 0x9100
}

func getUID(card *scard.Card) ([]byte, error) {
	for _, le := range []byte{0x00, 0x04} {
		apdu := []byte{0xFF, 0xCA, 0x00, 0x00, le}
		data, sw, err := transmit(card, apdu)
		if err == nil && swOK(sw) && len(data) > 0 {
			return data, nil
		}
	}
	return nil, fmt.Errorf("UID not available via GET DATA")
}

func selectNDEFApp(card *scard.Card) error {
	aid := []byte{0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01}
	apdu := []byte{0x00, 0xA4, 0x04, 0x00, byte(len(aid))}
	apdu = append(apdu, aid...)
	apdu = append(apdu, 0x00)
	_, sw, err := transmit(card, apdu)
	if err != nil {
		return err
	}
	if !swOK(sw) {
		return fmt.Errorf("SELECT NDEF app failed (SW1SW2=%04X)", sw)
	}
	return nil
}

// ============================================================================
// Crypto
// ============================================================================

type cipherBlock interface {
	Encrypt(dst, src []byte)
}

func xorBlock(dst, a, b []byte) {
	for i := 0; i < len(a) && i < len(b); i++ {
		dst[i] = a[i] ^ b[i]
	}
}

func leftShift1(dst, src []byte) {
	var carry byte
	for i := len(src) - 1; i >= 0; i-- {
		b := src[i]
		dst[i] = (b << 1) | carry
		carry = (b >> 7) & 1
	}
}

func generateCMACSubkeys(block cipherBlock) (k1, k2 []byte) {
	const Rb = 0x87
	zero := make([]byte, 16)
	L := make([]byte, 16)
	block.Encrypt(L, zero)

	k1 = make([]byte, 16)
	leftShift1(k1, L)
	if (L[0] & 0x80) != 0 {
		k1[15] ^= Rb
	}

	k2 = make([]byte, 16)
	leftShift1(k2, k1)
	if (k1[0] & 0x80) != 0 {
		k2[15] ^= Rb
	}
	return k1, k2
}

func aesCMAC(key, msg []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	k1, k2 := generateCMACSubkeys(block)

	n := (len(msg) + 15) / 16
	if n == 0 {
		n = 1
	}
	lastComplete := len(msg) != 0 && len(msg)%16 == 0

	last := make([]byte, 16)
	if lastComplete {
		copy(last, msg[(n-1)*16:])
		xorBlock(last, last, k1)
	} else {
		remain := len(msg) - (n-1)*16
		if remain > 0 {
			copy(last, msg[(n-1)*16:])
		}
		last[remain] = 0x80
		xorBlock(last, last, k2)
	}

	X := make([]byte, 16)
	Y := make([]byte, 16)
	for i := 0; i < n-1; i++ {
		blockStart := i * 16
		xorBlock(Y, X, msg[blockStart:blockStart+16])
		block.Encrypt(X, Y)
	}
	xorBlock(Y, X, last)
	block.Encrypt(X, Y)
	return X, nil
}

func truncateOddBytes(cmac []byte) []byte {
	out := make([]byte, 8)
	for i := 0; i < 8; i++ {
		out[i] = cmac[1+i*2]
	}
	return out
}

func aesCBCEncrypt(key, iv, data []byte) ([]byte, error) {
	if len(data)%16 != 0 {
		return nil, fmt.Errorf("CBC encrypt: data not block aligned")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(out, data)
	return out, nil
}

func aesCBCDecrypt(key, iv, data []byte) ([]byte, error) {
	if len(data)%16 != 0 {
		return nil, fmt.Errorf("CBC decrypt: data not block aligned")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(out, data)
	return out, nil
}

func aesECBEncrypt(key, blockIn []byte) ([]byte, error) {
	if len(blockIn) != 16 {
		return nil, fmt.Errorf("ECB input must be 16 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 16)
	block.Encrypt(out, blockIn)
	return out, nil
}

func padISO9797M2(data []byte) []byte {
	padLen := 16 - (len(data) % 16)
	out := make([]byte, len(data)+padLen)
	copy(out, data)
	out[len(data)] = 0x80
	return out
}

func unpadISO9797M2(data []byte) ([]byte, error) {
	idx := len(data) - 1
	for idx >= 0 && data[idx] == 0x00 {
		idx--
	}
	if idx < 0 || data[idx] != 0x80 {
		return nil, errors.New("bad padding")
	}
	return data[:idx], nil
}

func rotateLeft1(in []byte) []byte {
	out := make([]byte, len(in))
	if len(in) == 0 {
		return out
	}
	copy(out, in[1:])
	out[len(in)-1] = in[0]
	return out
}

func rotateRight1(in []byte) []byte {
	out := make([]byte, len(in))
	if len(in) == 0 {
		return out
	}
	out[0] = in[len(in)-1]
	copy(out[1:], in[:len(in)-1])
	return out
}

// ============================================================================
// Authentication
// ============================================================================

func authenticateEV2First(card *scard.Card, key []byte, keyNo byte) (*session, error) {
	apdu1 := []byte{0x90, 0x71, 0x00, 0x00, 0x02, keyNo, 0x00, 0x00}
	resp1, sw, err := transmit(card, apdu1)
	if err != nil {
		return nil, err
	}
	if sw != 0x91AF || len(resp1) != 16 {
		return nil, fmt.Errorf("auth step1 failed (SW=%04X len=%d)", sw, len(resp1))
	}

	iv0 := make([]byte, 16)
	rndB, err := aesCBCDecrypt(key, iv0, resp1)
	if err != nil {
		return nil, err
	}

	rndA := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, rndA); err != nil {
		return nil, err
	}

	rndBRot := rotateLeft1(rndB)
	rndAB := append(append([]byte{}, rndA...), rndBRot...)
	rndABEnc, err := aesCBCEncrypt(key, iv0, rndAB)
	if err != nil {
		return nil, err
	}

	apdu2 := make([]byte, 0, 5+len(rndABEnc)+1)
	apdu2 = append(apdu2, 0x90, 0xAF, 0x00, 0x00, 0x20)
	apdu2 = append(apdu2, rndABEnc...)
	apdu2 = append(apdu2, 0x00)
	resp2, sw, err := transmit(card, apdu2)
	if err != nil {
		return nil, err
	}
	if sw != 0x9100 || len(resp2) != 32 {
		return nil, fmt.Errorf("auth step2 failed (SW=%04X len=%d)", sw, len(resp2))
	}

	dec, err := aesCBCDecrypt(key, iv0, resp2)
	if err != nil {
		return nil, err
	}

	ti := dec[:4]
	rndARot := dec[4:20]
	rndACheck := rotateRight1(rndARot)
	if !bytes.Equal(rndACheck, rndA) {
		return nil, errors.New("rndA check failed")
	}

	sv1 := make([]byte, 32)
	sv2 := make([]byte, 32)
	copy(sv1, []byte{0xA5, 0x5A, 0x00, 0x01, 0x00, 0x80})
	copy(sv2, []byte{0x5A, 0xA5, 0x00, 0x01, 0x00, 0x80})
	copy(sv1[6:8], rndA[:2])
	copy(sv2[6:8], rndA[:2])
	for i := 0; i < 6; i++ {
		sv1[8+i] = rndA[2+i] ^ rndB[i]
		sv2[8+i] = rndA[2+i] ^ rndB[i]
	}
	copy(sv1[14:24], rndB[6:16])
	copy(sv2[14:24], rndB[6:16])
	copy(sv1[24:32], rndA[8:16])
	copy(sv2[24:32], rndA[8:16])

	kenc, err := aesCMAC(key, sv1)
	if err != nil {
		return nil, err
	}
	kmac, err := aesCMAC(key, sv2)
	if err != nil {
		return nil, err
	}

	s := &session{}
	copy(s.kenc[:], kenc)
	copy(s.kmac[:], kmac)
	copy(s.ti[:], ti)
	s.cmdCtr = 0
	return s, nil
}

func ssmCmdFull(card *scard.Card, sess *session, cmd byte, header, data []byte) ([]byte, error) {
	if sess == nil {
		return nil, errors.New("session is nil")
	}

	ivcIn := make([]byte, 16)
	ivcIn[0] = 0xA5
	ivcIn[1] = 0x5A
	copy(ivcIn[2:6], sess.ti[:])
	ivcIn[6] = byte(sess.cmdCtr & 0xFF)
	ivcIn[7] = byte((sess.cmdCtr >> 8) & 0xFF)
	ivc, err := aesECBEncrypt(sess.kenc[:], ivcIn)
	if err != nil {
		return nil, err
	}

	encData := []byte{}
	if len(data) > 0 {
		padded := padISO9797M2(data)
		encData, err = aesCBCEncrypt(sess.kenc[:], ivc, padded)
		if err != nil {
			return nil, err
		}
	}

	macInput := make([]byte, 0, len(header)+len(encData)+8)
	macInput = append(macInput, cmd)
	macInput = append(macInput, byte(sess.cmdCtr&0xFF), byte((sess.cmdCtr>>8)&0xFF))
	macInput = append(macInput, sess.ti[:]...)
	macInput = append(macInput, header...)
	macInput = append(macInput, encData...)

	cmac, err := aesCMAC(sess.kmac[:], macInput)
	if err != nil {
		return nil, err
	}
	mact := truncateOddBytes(cmac)

	dataLen := len(header) + len(encData) + len(mact)
	if dataLen > 255 {
		return nil, fmt.Errorf("APDU data too long")
	}
	apdu := make([]byte, 0, 6+dataLen)
	apdu = append(apdu, 0x90, cmd, 0x00, 0x00, byte(dataLen))
	apdu = append(apdu, header...)
	apdu = append(apdu, encData...)
	apdu = append(apdu, mact...)
	apdu = append(apdu, 0x00)

	resp, sw, err := transmit(card, apdu)
	if err != nil {
		return nil, err
	}
	if (sw & 0xFF00) != 0x9100 {
		return nil, fmt.Errorf("cmd 0x%02X failed (SW=%04X)", cmd, sw)
	}
	if len(resp) < 8 {
		return nil, fmt.Errorf("response too short (len=%d, SW=%04X)", len(resp), sw)
	}

	// Save original response for MAC calculation
	origResp := resp

	// First, determine if response is encrypted or plain by checking alignment
	respEncLen := len(resp) - 8
	if respEncLen < 0 {
		return nil, fmt.Errorf("response too short for MAC (len=%d)", len(resp))
	}
	isEncrypted := (respEncLen == 0 || respEncLen%16 == 0)

	// For ENCRYPTED responses: skip status byte (0x00)
	// For PLAIN responses: DON'T skip - the 0x00 might be the file type!
	if isEncrypted && len(resp) > 0 && resp[0] == 0x00 {
		resp = resp[1:]
		// Recalculate after skipping status
		respEncLen = len(resp) - 8
		if respEncLen < 0 {
			return nil, fmt.Errorf("response too short for MAC after status skip (len=%d)", len(resp))
		}
	}
	var respEnc []byte
	var respPlain []byte
	var respMac []byte

	if isEncrypted {
		// Standard encrypted response
		respEnc = resp[:respEncLen]
		respMac = resp[respEncLen:]
	} else {
		// Plain data response (happens when file CommMode is Plain)
		// Format: [Plain data] + [CMAC (8 bytes)]
		respPlain = resp[:respEncLen]
		respMac = resp[respEncLen:]
	}

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

	// Build MAC input - use ORIGINAL response (with status bytes) for MAC calculation
	// The MAC is calculated over: SW2 || CmdCtr || TI || [status bytes] || data
	// But we only use the data portion (excluding final MAC bytes)
	macDataWithStatus := origResp[:len(origResp)-8]

	macIn2 := make([]byte, 0, 8+len(macDataWithStatus))
	macIn2 = append(macIn2, byte(sw&0xFF))
	macIn2 = append(macIn2, byte(cmdCtr1&0xFF), byte((cmdCtr1>>8)&0xFF))
	macIn2 = append(macIn2, sess.ti[:]...)
	macIn2 = append(macIn2, macDataWithStatus...)

	cmac2, err := aesCMAC(sess.kmac[:], macIn2)
	if err != nil {
		return nil, err
	}
	mact2 := truncateOddBytes(cmac2)
	if !bytes.Equal(respMac, mact2) {
		return nil, errors.New("response MAC mismatch")
	}

	out := []byte{}
	if isEncrypted && respEncLen > 0 {
		// Decrypt encrypted data
		dec, err := aesCBCDecrypt(sess.kenc[:], ivr, respEnc)
		if err != nil {
			return nil, err
		}
		out, err = unpadISO9797M2(dec)
		if err != nil {
			return nil, err
		}
	} else if !isEncrypted {
		// Use plain data directly
		out = respPlain
	}

	sess.cmdCtr = cmdCtr1
	return out, nil
}

// ============================================================================
// File Settings
// ============================================================================

func getFileSettings(card *scard.Card, sess *session, fileNo byte) (*fileSettings, error) {
	out, err := ssmCmdFull(card, sess, 0xF5, []byte{fileNo}, nil)
	if err != nil {
		return nil, err
	}
	fs, err := parseFileSettings(out)
	if err != nil {
		return nil, err
	}
	fs.rawData = out // Store for later use in ChangeFileSettings
	return fs, nil
}

func getFileSettingsPlain(card *scard.Card, fileNo byte) (*fileSettings, error) {
	apdu := []byte{0x90, 0xF5, 0x00, 0x00, 0x01, fileNo, 0x00}
	resp, sw, err := transmit(card, apdu)
	if err != nil {
		return nil, err
	}
	if !swOK(sw) {
		return nil, fmt.Errorf("GetFileSettings failed (SW=%04X)", sw)
	}
	fs, err := parseFileSettings(resp)
	if err != nil {
		return nil, err
	}
	fs.rawData = resp
	return fs, nil
}

func parseFileSettings(data []byte) (*fileSettings, error) {
	if len(data) < 7 {
		return nil, errors.New("file settings too short")
	}
	fs := &fileSettings{}
	fs.fileType = data[0]
	fs.fileOption = data[1]
	fs.ar1 = data[2]
	fs.ar2 = data[3]
	fs.size = int(data[4]) | int(data[5])<<8 | int(data[6])<<16

	idx := 7
	if (fs.fileOption & 0x40) == 0 {
		return fs, nil
	}
	if len(data) < idx+3 {
		return nil, errors.New("file settings missing SDM fields")
	}
	fs.sdmOptions = data[idx]
	sdmAR := uint16(data[idx+1]) | (uint16(data[idx+2]) << 8)
	fs.sdmMeta = byte((sdmAR >> 12) & 0x0F)
	fs.sdmFile = byte((sdmAR >> 8) & 0x0F)
	fs.sdmCtr = byte(sdmAR & 0x0F)
	idx += 3

	// Parse conditional offset fields (mirroring buildChangeFileSettingsData logic)
	// UIDOffset: present if UID mirror enabled AND meta is plain (0xE)
	if (fs.sdmOptions&0x80) != 0 && fs.sdmMeta == 0x0E {
		if len(data) < idx+3 {
			return nil, errors.New("file settings missing UIDOffset")
		}
		fs.uidOffset = readU24le(data, idx)
		idx += 3
	}

	// SDMReadCtrOffset: present if ReadCtr mirror enabled AND meta is plain (0xE)
	if (fs.sdmOptions&0x40) != 0 && fs.sdmMeta == 0x0E {
		if len(data) < idx+3 {
			return nil, errors.New("file settings missing CtrOffset")
		}
		fs.ctrOffset = readU24le(data, idx)
		idx += 3
	}

	// PICCDataOffset: present if meta is NOT plain (encrypted PICC data)
	if fs.sdmMeta != 0x0E && fs.sdmMeta != 0x0F {
		if len(data) < idx+3 {
			return nil, errors.New("file settings missing PICCDataOffset")
		}
		fs.uidOffset = readU24le(data, idx) // Reuse uidOffset field for PICC data
		idx += 3
	}

	// SDMMACInputOffset + SDMMACOffset: present if SDMFileRead is not Denied
	if fs.sdmFile != 0x0F {
		if len(data) < idx+6 {
			return nil, errors.New("file settings missing MAC offsets")
		}
		fs.macInputOffset = readU24le(data, idx)
		fs.macOffset = readU24le(data, idx+3)
		idx += 6
	}

	// SDMENCOffset + SDMENCLength: present if encrypted file data enabled
	if (fs.sdmOptions & 0x10) != 0 {
		if len(data) < idx+6 {
			return nil, errors.New("file settings missing ENC offsets")
		}
		fs.encOffset = readU24le(data, idx)
		fs.encLength = readU24le(data, idx+3)
		idx += 6
	}

	// SDMReadCtrLimit: present if ReadCtr limit enabled
	if (fs.sdmOptions & 0x20) != 0 {
		if len(data) < idx+3 {
			return nil, errors.New("file settings missing CtrLimit")
		}
		fs.ctrLimit = readU24le(data, idx)
		idx += 3
	}

	return fs, nil
}

func changeFileSettings(card *scard.Card, sess *session, fileNo byte, newSettings []byte) error {
	_, err := ssmCmdFull(card, sess, 0x5F, []byte{fileNo}, newSettings)
	return err
}

func commModeLabel(fileOption byte) string {
	mode := fileOption & 0x03
	switch mode {
	case 0x00:
		return "Plain"
	case 0x01:
		return "MAC"
	case 0x03:
		return "Full"
	default:
		return fmt.Sprintf("Unknown(0x%02X)", mode)
	}
}

func accessLabel(keyNo byte) string {
	switch keyNo {
	case 0xE:
		return "Free"
	case 0xF:
		return "Denied"
	case 0:
		return "Key 0 (AppMaster)"
	case 1:
		return "Key 1 (SDM)"
	case 2:
		return "Key 2 (File 2 Write)"
	case 3:
		return "Key 3"
	case 4:
		return "Key 4"
	default:
		return fmt.Sprintf("Key %d", keyNo)
	}
}

func displayFileSettings(fileNo byte, name string, fs *fileSettings) {
	fmt.Printf("\nFile %d (%s):\n", fileNo, name)
	fmt.Printf("  CommMode:     %s\n", commModeLabel(fs.fileOption))

	readKey := (fs.ar2 >> 4) & 0x0F
	writeKey := fs.ar2 & 0x0F
	readWriteKey := (fs.ar1 >> 4) & 0x0F
	changeAccessKey := fs.ar1 & 0x0F

	fmt.Printf("  Read:         %s\n", accessLabel(readKey))
	fmt.Printf("  Write:        %s\n", accessLabel(writeKey))
	fmt.Printf("  ReadWrite:    %s\n", accessLabel(readWriteKey))
	fmt.Printf("  ChangeAccess: %s\n", accessLabel(changeAccessKey))

	if (fs.fileOption & 0x40) != 0 {
		fmt.Printf("  SDM:          Enabled\n")
		// Display SDM details with correct bit positions (per datasheet)
		fmt.Printf("    UID mirror:       %s\n", onOff((fs.sdmOptions&0x80) != 0))       // Bit 7
		fmt.Printf("    ReadCtr mirror:   %s\n", onOff((fs.sdmOptions&0x40) != 0))       // Bit 6
		fmt.Printf("    ReadCtr limit:    %s\n", onOff((fs.sdmOptions&0x20) != 0))       // Bit 5
		fmt.Printf("    Enc file data:    %s\n", onOff((fs.sdmOptions&0x10) != 0))       // Bit 4
		fmt.Printf("    ASCII encoding:   %s\n", onOff((fs.sdmOptions&0x01) != 0))       // Bit 0
		fmt.Printf("    SDMMetaRead:      %s\n", accessLabel(fs.sdmMeta))
		fmt.Printf("    SDMFileRead:      %s\n", accessLabel(fs.sdmFile))
		fmt.Printf("    SDMCtrRet:        %s\n", accessLabel(fs.sdmCtr))
	}
}

// ============================================================================
// Key file operations
// ============================================================================

func loadKeyHexFile(path string) ([]byte, error) {
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

func loadAllHexKeys(dir string) ([]keyFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var keys []keyFile
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.ToLower(filepath.Ext(e.Name())) != ".hex" {
			continue
		}

		path := filepath.Join(dir, e.Name())
		key, err := loadKeyHexFile(path)
		if err != nil {
			continue // Skip invalid key files
		}

		keys = append(keys, keyFile{
			name: e.Name(),
			key:  key,
		})
	}

	return keys, nil
}

// ============================================================================
// Helpers
// ============================================================================

func hexUpper(b []byte) string {
	return strings.ToUpper(hex.EncodeToString(b))
}

func u24le(v uint32) []byte {
	return []byte{byte(v & 0xFF), byte((v >> 8) & 0xFF), byte((v >> 16) & 0xFF)}
}

func readU24le(data []byte, offset int) uint32 {
	if offset+3 > len(data) {
		return 0
	}
	return uint32(data[offset]) | (uint32(data[offset+1]) << 8) | (uint32(data[offset+2]) << 16)
}

func onOff(b bool) string {
	if b {
		return "On"
	}
	return "Off"
}

func selectSDMAccessKey(prompt string, current byte, allowDenied bool) byte {
	items := []string{}
	values := []byte{}

	// Free access
	items = append(items, "Free")
	values = append(values, 0xE)

	// Denied (optional)
	if allowDenied {
		items = append(items, "Denied")
		values = append(values, 0xF)
	}

	// Keys 0-4
	keyLabels := []string{"Key 0 (AppMaster)", "Key 1 (SDM)", "Key 2 (File 2 Write)", "Key 3", "Key 4"}
	for i, label := range keyLabels {
		items = append(items, label)
		values = append(values, byte(i))
	}

	// Mark current
	for i, val := range values {
		if val == current {
			items[i] = items[i] + " (current)"
			break
		}
	}

	idx := selectMenu(prompt, items)
	if idx < 0 || idx >= len(values) {
		return current
	}
	return values[idx]
}

// ============================================================================
// Interactive Menu
// ============================================================================

func selectMenu(prompt string, items []string) int {
	if len(items) == 0 {
		return -1
	}

	// Put stdin into raw mode
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error setting raw mode: %v\r\n", err)
		return -1
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	selected := 0

	// Initial render
	fmt.Printf("%s\r\n", prompt)
	for i, item := range items {
		if i == selected {
			fmt.Printf("> %s\r\n", item)
		} else {
			fmt.Printf("  %s\r\n", item)
		}
	}

	// Read loop
	buf := make([]byte, 3)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil {
			break
		}

		if n == 1 {
			// Single byte commands
			switch buf[0] {
			case 0x0D, 0x0A: // Enter
				// Move cursor down past menu, then restore terminal
				fmt.Printf("\r\n")
				return selected
			case 0x03: // Ctrl-C
				term.Restore(int(os.Stdin.Fd()), oldState)
				fmt.Printf("\r\n")
				os.Exit(0)
			}
		} else if n == 3 && buf[0] == 0x1B && buf[1] == '[' {
			// Arrow keys
			needRedraw := false
			switch buf[2] {
			case 'A': // Up arrow
				if selected > 0 {
					selected--
					needRedraw = true
				}
			case 'B': // Down arrow
				if selected < len(items)-1 {
					selected++
					needRedraw = true
				}
			}

			if needRedraw {
				// Move cursor up to start of menu (skip prompt line)
				fmt.Printf("\033[%dA", len(items))
				// Redraw all items
				for i, item := range items {
					// Clear line and return to column 0
					fmt.Print("\033[2K\r")
					if i == selected {
						fmt.Printf("> %s\r\n", item)
					} else {
						fmt.Printf("  %s\r\n", item)
					}
				}
			}
		}
	}

	return selected
}

// ============================================================================
// Main
// ============================================================================

func main() {
	verbose := flag.Bool("v", false, "enable debug logging")
	logFormat := flag.String("log-format", "text", "log format: text or json")
	flag.Parse()

	// Configure slog
	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	opts := &slog.HandlerOptions{Level: level}
	if *logFormat == "json" {
		slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, opts)))
	} else {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, opts)))
	}

	fmt.Println("=== NTAG 424 DNA File Permissions Editor ===")
	fmt.Println()

	// Establish context
	ctx, err := scard.EstablishContext()
	if err != nil {
		fmt.Printf("Error establishing context: %v\n", err)
		os.Exit(1)
	}
	defer ctx.Release()

	// List readers
	readers, err := ctx.ListReaders()
	if err != nil || len(readers) == 0 {
		fmt.Printf("Error: no card readers available\n")
		os.Exit(1)
	}

	fmt.Printf("Using reader: %s\n", readers[0])

	// Connect to card
	card, err := ctx.Connect(readers[0], scard.ShareShared, scard.ProtocolAny)
	if err != nil {
		fmt.Printf("Error connecting to card: %v\n", err)
		os.Exit(1)
	}
	defer card.Disconnect(scard.LeaveCard)

	// Get UID
	uid, err := getUID(card)
	if err != nil {
		fmt.Printf("Error reading UID: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("UID: %s\n", hexUpper(uid))
	fmt.Println()

	// Select NDEF app
	if err := selectNDEFApp(card); err != nil {
		fmt.Printf("Error selecting NDEF app: %v\n", err)
		os.Exit(1)
	}

	// Probe slot 0 (AppMasterKey)
	fmt.Println("Probing AppMasterKey (slot 0)...")

	// Build key list: all-zero + key files
	type keyInfo struct {
		key   []byte
		label string
	}

	keys := []keyInfo{
		{make([]byte, 16), "all-zero"},
	}

	// Load keys from ../keys/
	keyFiles, err := loadAllHexKeys("../keys")
	if err == nil {
		for _, kf := range keyFiles {
			keys = append(keys, keyInfo{kf.key, kf.name})
		}
	}

	// Try to find AppMasterKey
	var masterKey []byte
	var masterKeyLabel string
	found := false

	for _, k := range keys {
		if err := selectNDEFApp(card); err != nil {
			continue
		}
		if _, err := authenticateEV2First(card, k.key, 0); err == nil {
			masterKey = k.key
			masterKeyLabel = k.label
			found = true
			break
		}
	}

	if !found {
		fmt.Println("Error: Cannot authenticate with AppMasterKey (slot 0)")
		fmt.Println("Please ensure the correct key is available in ../keys/ or the card uses the default all-zero key.")
		os.Exit(1)
	}

	fmt.Printf("AppMasterKey: %s\n", masterKeyLabel)
	fmt.Println()

	// Re-authenticate with slot 0
	if err := selectNDEFApp(card); err != nil {
		fmt.Printf("Error re-selecting NDEF app: %v\n", err)
		os.Exit(1)
	}

	sess, err := authenticateEV2First(card, masterKey, 0)
	if err != nil {
		fmt.Printf("Authentication failed: %v\n", err)
		os.Exit(1)
	}

	// Read file settings for files 1, 2, 3
	fmt.Println("Reading file settings...")

	fileInfos := []struct {
		no   byte
		name string
	}{
		{1, "CC"},
		{2, "NDEF"},
		{3, "Proprietary"},
	}

	fileSettings := make(map[byte]*fileSettings)

	for _, info := range fileInfos {
		// Try plain mode first (no authentication needed)
		fs, err := getFileSettingsPlain(card, info.no)
		if err != nil {
			// Plain mode failed - try secure mode with authentication
			if err := selectNDEFApp(card); err != nil {
				fmt.Printf("Warning: Could not re-select NDEF app for file %d: %v\n", info.no, err)
				continue
			}

			sess, authErr := authenticateEV2First(card, masterKey, 0)
			if authErr != nil {
				fmt.Printf("Warning: Could not authenticate for file %d: %v\n", info.no, authErr)
				// Reset card state before next file
				selectNDEFApp(card)
				continue
			}

			fs, err = getFileSettings(card, sess, info.no)
			if err != nil {
				fmt.Printf("Warning: Could not read file %d settings (plain or secure): %v\n", info.no, err)
				// Reset card state before next file
				selectNDEFApp(card)
				continue
			}

			// Reset card state after successful secure read, so next file can try plain mode
			selectNDEFApp(card)
		}
		fileSettings[info.no] = fs
		displayFileSettings(info.no, info.name, fs)
	}

	if len(fileSettings) == 0 {
		fmt.Println("\nError: No file settings could be read.")
		os.Exit(1)
	}

	fmt.Println()

	// Select file to edit
	fileItems := []string{}
	fileOrder := []byte{}

	for _, info := range fileInfos {
		if _, ok := fileSettings[info.no]; ok {
			fileItems = append(fileItems, fmt.Sprintf("File %d (%s)", info.no, info.name))
			fileOrder = append(fileOrder, info.no)
		}
	}

	selectedFileIdx := selectMenu("Select file to edit:", fileItems)
	if selectedFileIdx < 0 {
		fmt.Println("Invalid selection.")
		os.Exit(1)
	}
	targetFile := fileOrder[selectedFileIdx]
	currentSettings := fileSettings[targetFile]

	fmt.Printf("\nEditing File %d\n", targetFile)
	fmt.Println()

	// Edit CommMode
	commModeItems := []string{"Plain", "MAC", "Full"}
	currentCommMode := currentSettings.fileOption & 0x03
	var currentCommIdx int
	switch currentCommMode {
	case 0x00:
		currentCommIdx = 0
	case 0x01:
		currentCommIdx = 1
	case 0x03:
		currentCommIdx = 2
	}

	// Highlight current selection
	for i := range commModeItems {
		if i == currentCommIdx {
			commModeItems[i] = commModeItems[i] + " (current)"
		}
	}

	commModeIdx := selectMenu("Select CommMode:", commModeItems)
	var newCommMode byte
	switch commModeIdx {
	case 0:
		newCommMode = 0x00
	case 1:
		newCommMode = 0x01
	case 2:
		newCommMode = 0x03
	default:
		fmt.Println("Invalid selection.")
		os.Exit(1)
	}

	// Edit Read key
	readAccessItems := []string{"Free", "Denied", "Key 0 (AppMaster)", "Key 1 (SDM)", "Key 2 (File 2 Write)", "Key 3", "Key 4"}
	currentReadKey := (currentSettings.ar2 >> 4) & 0x0F
	for i := range readAccessItems {
		var expectedKey byte
		if i == 0 {
			expectedKey = 0xE
		} else if i == 1 {
			expectedKey = 0xF
		} else {
			expectedKey = byte(i - 2)
		}
		if expectedKey == currentReadKey {
			readAccessItems[i] = readAccessItems[i] + " (current)"
		}
	}

	readKeyIdx := selectMenu("Select Read key:", readAccessItems)
	var newReadKey byte
	if readKeyIdx == 0 {
		newReadKey = 0xE
	} else if readKeyIdx == 1 {
		newReadKey = 0xF
	} else {
		newReadKey = byte(readKeyIdx - 2)
	}

	// Edit Write key
	writeAccessItems := []string{"Free", "Denied", "Key 0 (AppMaster)", "Key 1 (SDM)", "Key 2 (File 2 Write)", "Key 3", "Key 4"}
	currentWriteKey := currentSettings.ar2 & 0x0F
	for i := range writeAccessItems {
		var expectedKey byte
		if i == 0 {
			expectedKey = 0xE
		} else if i == 1 {
			expectedKey = 0xF
		} else {
			expectedKey = byte(i - 2)
		}
		if expectedKey == currentWriteKey {
			writeAccessItems[i] = writeAccessItems[i] + " (current)"
		}
	}

	writeKeyIdx := selectMenu("Select Write key:", writeAccessItems)
	var newWriteKey byte
	if writeKeyIdx == 0 {
		newWriteKey = 0xE
	} else if writeKeyIdx == 1 {
		newWriteKey = 0xF
	} else {
		newWriteKey = byte(writeKeyIdx - 2)
	}

	// Edit ReadWrite key
	readWriteAccessItems := []string{"Free", "Denied", "Key 0 (AppMaster)", "Key 1 (SDM)", "Key 2 (File 2 Write)", "Key 3", "Key 4"}
	currentReadWriteKey := (currentSettings.ar1 >> 4) & 0x0F
	for i := range readWriteAccessItems {
		var expectedKey byte
		if i == 0 {
			expectedKey = 0xE
		} else if i == 1 {
			expectedKey = 0xF
		} else {
			expectedKey = byte(i - 2)
		}
		if expectedKey == currentReadWriteKey {
			readWriteAccessItems[i] = readWriteAccessItems[i] + " (current)"
		}
	}

	readWriteKeyIdx := selectMenu("Select ReadWrite key:", readWriteAccessItems)
	var newReadWriteKey byte
	if readWriteKeyIdx == 0 {
		newReadWriteKey = 0xE
	} else if readWriteKeyIdx == 1 {
		newReadWriteKey = 0xF
	} else {
		newReadWriteKey = byte(readWriteKeyIdx - 2)
	}

	// Edit ChangeAccess key (no Free/Denied option)
	changeAccessItems := []string{"Key 0 (AppMaster)", "Key 1 (SDM)", "Key 2 (File 2 Write)", "Key 3", "Key 4"}
	currentChangeAccessKey := currentSettings.ar1 & 0x0F
	for i := range changeAccessItems {
		if byte(i) == currentChangeAccessKey {
			changeAccessItems[i] = changeAccessItems[i] + " (current)"
		}
	}

	changeAccessKeyIdx := selectMenu("Select ChangeAccess key:", changeAccessItems)
	newChangeAccessKey := byte(changeAccessKeyIdx)

	// SDM editing
	var sdmEdited bool
	var newSDMOptions byte
	var newSDMMeta byte
	var newSDMFile byte
	var newSDMCtr byte
	sdmEnabled := (currentSettings.fileOption & 0x40) != 0
	sdmDisabled := false

	if sdmEnabled {
		editSDMItems := []string{"No (preserve current SDM settings)", "Yes (edit SDM settings)"}
		editSDMIdx := selectMenu("Edit SDM settings?", editSDMItems)

		if editSDMIdx == 1 {
			// Ask if user wants to keep or disable SDM
			sdmToggleItems := []string{"Keep enabled", "Disable SDM"}
			sdmToggleIdx := selectMenu("SDM:", sdmToggleItems)

			if sdmToggleIdx == 1 {
				// User wants to disable SDM
				sdmDisabled = true
			} else {
				// User wants to keep SDM enabled - edit settings
				sdmEdited = true

				// Copy current settings as starting point
				newSDMOptions = currentSettings.sdmOptions
				newSDMMeta = currentSettings.sdmMeta
				newSDMFile = currentSettings.sdmFile
				newSDMCtr = currentSettings.sdmCtr

				// UID mirroring toggle
				uidMirrorItems := []string{"Off", "On"}
				for i := range uidMirrorItems {
					if ((newSDMOptions&0x80) != 0) == (i == 1) {
						uidMirrorItems[i] = uidMirrorItems[i] + " (current)"
					}
				}
				uidMirrorIdx := selectMenu("UID mirroring:", uidMirrorItems)
				if uidMirrorIdx == 1 {
					newSDMOptions |= 0x80
				} else {
					newSDMOptions &= ^byte(0x80)
				}

				// ReadCtr mirroring toggle
				ctrMirrorItems := []string{"Off", "On"}
				for i := range ctrMirrorItems {
					if ((newSDMOptions&0x40) != 0) == (i == 1) {
						ctrMirrorItems[i] = ctrMirrorItems[i] + " (current)"
					}
				}
				ctrMirrorIdx := selectMenu("ReadCtr mirroring:", ctrMirrorItems)
				if ctrMirrorIdx == 1 {
					newSDMOptions |= 0x40
				} else {
					newSDMOptions &= ^byte(0x40)
				}

				// ReadCtr limit toggle
				ctrLimitItems := []string{"Off", "On"}
				for i := range ctrLimitItems {
					if ((newSDMOptions&0x20) != 0) == (i == 1) {
						ctrLimitItems[i] = ctrLimitItems[i] + " (current)"
					}
				}
				ctrLimitIdx := selectMenu("ReadCtr limit:", ctrLimitItems)
				if ctrLimitIdx == 1 {
					newSDMOptions |= 0x20
				} else {
					newSDMOptions &= ^byte(0x20)
				}

				// Encrypted file data toggle
				encFileItems := []string{"Off", "On"}
				for i := range encFileItems {
					if ((newSDMOptions&0x10) != 0) == (i == 1) {
						encFileItems[i] = encFileItems[i] + " (current)"
					}
				}
				encFileIdx := selectMenu("Encrypted file data:", encFileItems)
				if encFileIdx == 1 {
					newSDMOptions |= 0x10
				} else {
					newSDMOptions &= ^byte(0x10)
				}

				// ASCII encoding toggle
				asciiItems := []string{"Off", "On"}
				for i := range asciiItems {
					if ((newSDMOptions&0x01) != 0) == (i == 1) {
						asciiItems[i] = asciiItems[i] + " (current)"
					}
				}
				asciiIdx := selectMenu("ASCII encoding:", asciiItems)
				if asciiIdx == 1 {
					newSDMOptions |= 0x01
				} else {
					newSDMOptions &= ^byte(0x01)
				}

				// SDMMetaRead key
				newSDMMeta = selectSDMAccessKey("SDMMetaRead key:", currentSettings.sdmMeta, false)

				// SDMFileRead key
				newSDMFile = selectSDMAccessKey("SDMFileRead key:", currentSettings.sdmFile, true)

				// SDMCtrRet key
				newSDMCtr = selectSDMAccessKey("SDMCtrRet key:", currentSettings.sdmCtr, true)

				// Structural change detection
				oldMetaIsPlain := currentSettings.sdmMeta == 0x0E
				newMetaIsPlain := newSDMMeta == 0x0E
				oldMetaIsKey := currentSettings.sdmMeta != 0x0E && currentSettings.sdmMeta != 0x0F
				newMetaIsKey := newSDMMeta != 0x0E && newSDMMeta != 0x0F

				oldFileNotDenied := currentSettings.sdmFile != 0x0F
				newFileNotDenied := newSDMFile != 0x0F

				oldUIDMirror := (currentSettings.sdmOptions & 0x80) != 0
				newUIDMirror := (newSDMOptions & 0x80) != 0
				oldCtrMirror := (currentSettings.sdmOptions & 0x40) != 0
				newCtrMirror := (newSDMOptions & 0x40) != 0
				oldEncFile := (currentSettings.sdmOptions & 0x10) != 0
				newEncFile := (newSDMOptions & 0x10) != 0
				oldCtrLimit := (currentSettings.sdmOptions & 0x20) != 0
				newCtrLimit := (newSDMOptions & 0x20) != 0

				structuralChange := false
				var changeReason string

				// Check for structural changes
				if oldMetaIsPlain != newMetaIsPlain || oldMetaIsKey != newMetaIsKey {
					structuralChange = true
					changeReason = "SDMMetaRead changed between plain (Free) and encrypted (Key 0-4)"
				} else if oldFileNotDenied != newFileNotDenied {
					structuralChange = true
					changeReason = "SDMFileRead changed to/from Denied (affects MAC offset fields)"
				} else if oldEncFile != newEncFile {
					structuralChange = true
					changeReason = "Encrypted file data toggled (affects ENC offset fields)"
				} else if oldCtrLimit != newCtrLimit {
					structuralChange = true
					changeReason = "ReadCtr limit toggled (affects CtrLimit field)"
				} else if oldMetaIsPlain && newMetaIsPlain {
					// Only check UID/Ctr mirror changes if meta is plain
					if oldUIDMirror != newUIDMirror {
						structuralChange = true
						changeReason = "UID mirror toggled while MetaRead is plain (affects UIDOffset field)"
					} else if oldCtrMirror != newCtrMirror {
						structuralChange = true
						changeReason = "ReadCtr mirror toggled while MetaRead is plain (affects CtrOffset field)"
					}
				}

				if structuralChange {
					fmt.Printf("\n=== ERROR: Structural Change Detected ===\n")
					fmt.Printf("Reason: %s\n\n", changeReason)
					fmt.Printf("This change would alter the offset field structure in the SDM configuration.\n")
					fmt.Printf("Offsets depend on the NDEF template content and cannot be safely modified\n")
					fmt.Printf("without rewriting the entire template.\n\n")
					fmt.Printf("Please use the 'update' tool to re-provision the tag with new SDM settings.\n")
					os.Exit(1)
				}
			}
		}
	} else {
		// SDM not currently enabled - offer to enable it
		enableSDMItems := []string{"No (keep SDM disabled)", "Yes (enable SDM)"}
		enableSDMIdx := selectMenu("Enable SDM on this file?", enableSDMItems)

		if enableSDMIdx == 1 {
			fmt.Printf("\n=== Cannot Enable SDM ===\n")
			fmt.Printf("Enabling SDM requires configuring offset fields that depend on the\n")
			fmt.Printf("NDEF template structure. These offsets cannot be safely calculated\n")
			fmt.Printf("without knowing the template content.\n\n")
			fmt.Printf("To enable SDM on this file, please use the 'update' tool to\n")
			fmt.Printf("re-provision the tag with SDM configuration.\n")
			os.Exit(1)
		}
		// User chose not to enable SDM, continue with normal permission editing
	}

	// Show summary
	fmt.Println("\n=== Summary ===")
	fmt.Printf("File %d - Changing:\n", targetFile)
	fmt.Printf("  CommMode:     %s -> %s\n",
		commModeLabel(currentSettings.fileOption),
		commModeLabel(newCommMode))
	fmt.Printf("  Read:         %s -> %s\n",
		accessLabel((currentSettings.ar2>>4)&0x0F),
		accessLabel(newReadKey))
	fmt.Printf("  Write:        %s -> %s\n",
		accessLabel(currentSettings.ar2&0x0F),
		accessLabel(newWriteKey))
	fmt.Printf("  ReadWrite:    %s -> %s\n",
		accessLabel((currentSettings.ar1>>4)&0x0F),
		accessLabel(newReadWriteKey))
	fmt.Printf("  ChangeAccess: %s -> %s\n",
		accessLabel(currentSettings.ar1&0x0F),
		accessLabel(newChangeAccessKey))

	// Show SDM changes if applicable
	if sdmEnabled && sdmDisabled {
		fmt.Printf("  SDM:          Enabled -> DISABLED\n")
	} else if sdmEnabled && sdmEdited {
		fmt.Println("  SDM changes:")
		if ((currentSettings.sdmOptions&0x80) != 0) != ((newSDMOptions&0x80) != 0) {
			fmt.Printf("    UID mirror:       %s -> %s\n",
				onOff((currentSettings.sdmOptions&0x80) != 0),
				onOff((newSDMOptions&0x80) != 0))
		}
		if ((currentSettings.sdmOptions&0x40) != 0) != ((newSDMOptions&0x40) != 0) {
			fmt.Printf("    ReadCtr mirror:   %s -> %s\n",
				onOff((currentSettings.sdmOptions&0x40) != 0),
				onOff((newSDMOptions&0x40) != 0))
		}
		if ((currentSettings.sdmOptions&0x20) != 0) != ((newSDMOptions&0x20) != 0) {
			fmt.Printf("    ReadCtr limit:    %s -> %s\n",
				onOff((currentSettings.sdmOptions&0x20) != 0),
				onOff((newSDMOptions&0x20) != 0))
		}
		if ((currentSettings.sdmOptions&0x10) != 0) != ((newSDMOptions&0x10) != 0) {
			fmt.Printf("    Enc file data:    %s -> %s\n",
				onOff((currentSettings.sdmOptions&0x10) != 0),
				onOff((newSDMOptions&0x10) != 0))
		}
		if ((currentSettings.sdmOptions&0x01) != 0) != ((newSDMOptions&0x01) != 0) {
			fmt.Printf("    ASCII encoding:   %s -> %s\n",
				onOff((currentSettings.sdmOptions&0x01) != 0),
				onOff((newSDMOptions&0x01) != 0))
		}
		if currentSettings.sdmMeta != newSDMMeta {
			fmt.Printf("    SDMMetaRead:      %s -> %s\n",
				accessLabel(currentSettings.sdmMeta),
				accessLabel(newSDMMeta))
		}
		if currentSettings.sdmFile != newSDMFile {
			fmt.Printf("    SDMFileRead:      %s -> %s\n",
				accessLabel(currentSettings.sdmFile),
				accessLabel(newSDMFile))
		}
		if currentSettings.sdmCtr != newSDMCtr {
			fmt.Printf("    SDMCtrRet:        %s -> %s\n",
				accessLabel(currentSettings.sdmCtr),
				accessLabel(newSDMCtr))
		}
	}

	fmt.Println()

	// Confirm
	fmt.Print("Apply these changes? (y/n): ")
	reader := bufio.NewReader(os.Stdin)
	confirmInput, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Error reading input: %v\n", err)
		os.Exit(1)
	}
	confirmInput = strings.ToLower(strings.TrimSpace(confirmInput))
	if confirmInput != "y" && confirmInput != "yes" {
		fmt.Println("Cancelled.")
		os.Exit(0)
	}

	// Build new settings payload
	var newSettingsData []byte

	// Build AR bytes
	newAR1 := (newReadWriteKey << 4) | newChangeAccessKey
	newAR2 := (newReadKey << 4) | newWriteKey

	if sdmEnabled && !sdmDisabled {
		// SDM is/remains enabled
		newFileOption := (newCommMode & 0x03) | 0x40

		if sdmEdited {
			// SDM settings were edited - rebuild SDM bytes
			newSettingsData = []byte{newFileOption, newAR1, newAR2, newSDMOptions}

			// Build SDMAccessRights (2 bytes)
			sdmAR := uint16((uint16(newSDMMeta&0x0F) << 12) | (uint16(newSDMFile&0x0F) << 8) | (0x0F << 4) | uint16(newSDMCtr&0x0F))
			newSettingsData = append(newSettingsData, byte(sdmAR&0xFF), byte((sdmAR>>8)&0xFF))

			// Append offset fields from rawData (starting at byte 10)
			// These are preserved as structural changes are blocked
			if len(currentSettings.rawData) > 10 {
				newSettingsData = append(newSettingsData, currentSettings.rawData[10:]...)
			}
		} else {
			// SDM not edited - preserve all SDM data from rawData
			// rawData format: [0] FileType [1] FileOption [2] AR1 [3] AR2 [4-6] Size [7+] SDM data
			// payload format: [0] FileOption [1] AR1 [2] AR2 [3+] SDM data
			newSettingsData = []byte{newFileOption, newAR1, newAR2}
			if len(currentSettings.rawData) > 7 {
				newSettingsData = append(newSettingsData, currentSettings.rawData[7:]...)
			}
		}
	} else {
		// SDM disabled or was disabled
		newFileOption := newCommMode & 0x03
		newSettingsData = []byte{newFileOption, newAR1, newAR2}
	}

	// Send ChangeFileSettings
	fmt.Println("\nSending ChangeFileSettings command...")

	// Re-authenticate with slot 0
	if err := selectNDEFApp(card); err != nil {
		fmt.Printf("Error re-selecting NDEF app: %v\n", err)
		os.Exit(1)
	}

	sess, err = authenticateEV2First(card, masterKey, 0)
	if err != nil {
		fmt.Printf("Authentication failed: %v\n", err)
		os.Exit(1)
	}

	err = changeFileSettings(card, sess, targetFile, newSettingsData)
	if err != nil {
		fmt.Printf("ChangeFileSettings failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Change successful!")
	fmt.Println()

	// Verify by re-reading file settings
	fmt.Println("Verifying changes...")

	if err := selectNDEFApp(card); err != nil {
		fmt.Printf("Error re-selecting NDEF app: %v\n", err)
		os.Exit(1)
	}

	sess, err = authenticateEV2First(card, masterKey, 0)
	if err != nil {
		fmt.Printf("Authentication failed: %v\n", err)
		os.Exit(1)
	}

	verifyFS, err := getFileSettings(card, sess, targetFile)
	if err != nil {
		fmt.Printf("Warning: Could not verify file settings: %v\n", err)
	} else {
		fmt.Println()
		displayFileSettings(targetFile, "", verifyFS)
		fmt.Println()
		fmt.Println("SUCCESS: File permissions updated!")
	}
}
