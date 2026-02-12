package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/ebfe/scard"
	"github.com/barnettlynn/nfctools/pkg/ntag424"
)

// Wrapper functions to bridge ro tool to shared library

func loadAllHexKeys(dir string) ([]keyFile, error) {
	keys, err := ntag424.LoadAllHexKeys(dir)
	if err != nil {
		return nil, err
	}
	result := make([]keyFile, len(keys))
	for i, k := range keys {
		result[i] = keyFile{name: k.Name, key: k.Key}
	}
	return result, nil
}

func loadKeyHexFile(path string) ([]byte, error) {
	return ntag424.LoadKeyHexFile(path)
}

func authenticateEV2First(card *scard.Card, key []byte, keyNo byte) (*session, error) {
	sess, err := ntag424.AuthenticateEV2First(card, key, keyNo)
	if err != nil {
		return nil, err
	}
	return fromNtag424Session(sess), nil
}

func getFileSettingsPlain(card *scard.Card, fileNo byte) (*fileSettings, error) {
	fs, err := ntag424.GetFileSettingsPlain(card, fileNo)
	if err != nil {
		return nil, err
	}
	// Convert to local fileSettings type
	return convertFileSettings(fs), nil
}

func getFileSettingsSecure(card *scard.Card, sess *session, fileNo byte) (*fileSettings, error) {
	fs, err := ntag424.GetFileSettingsSecure(card, toNtag424Session(sess), fileNo)
	if err != nil {
		return nil, err
	}
	return convertFileSettings(fs), nil
}

func getKeySettingsPlain(card *scard.Card) (keySettings byte, maxKeys byte, err error) {
	apdu := []byte{0x90, 0x45, 0x00, 0x00, 0x00}
	resp, sw, err := transmit(card, apdu)
	if err != nil {
		return 0, 0, err
	}
	if !swOK(sw) || len(resp) < 2 {
		return 0, 0, fmt.Errorf("GetKeySettings failed (SW=%04X, len=%d)", sw, len(resp))
	}
	return resp[0], resp[1], nil
}

func getKeySettingsSecure(card *scard.Card, sess *session) (keySettings byte, maxKeys byte, err error) {
	// For now, fall back to plain - can be enhanced later
	return getKeySettingsPlain(card)
}

func ssmCmdFull(card *scard.Card, sess *session, cmd byte, header, data []byte) ([]byte, error) {
	return ntag424.SsmCmdFull(card, toNtag424Session(sess), cmd, header, data)
}

func findDefaultKeyFile() (string, error) {
	// Check common key file locations
	paths := []string{
		"../keys/AppMasterKey.hex",
		"keys/AppMasterKey.hex",
		"AppMasterKey.hex",
	}
	for _, p := range paths {
		if fileExists(p) {
			return p, nil
		}
	}
	return "", fmt.Errorf("key file not found in common locations")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Helper to convert ntag424.FileSettings to local fileSettings
func convertFileSettings(fs *ntag424.FileSettings) *fileSettings {
	return &fileSettings{
		fileType:   fs.FileType,
		fileOption: fs.FileOption,
		ar1:        fs.AR1,
		ar2:        fs.AR2,
		size:       fs.Size,
		sdmOptions: fs.SDMOptions,
		sdmMeta:    fs.SDMMeta,
		sdmFile:    fs.SDMFile,
		sdmCtr:     fs.SDMCtr,
	}
}

type TagVersion struct {
	HWVendorID    byte
	HWType        byte
	HWSubType     byte
	HWMajorVer    byte
	HWMinorVer    byte
	HWStorageSize byte
	HWProtocol    byte
	SWVendorID    byte
	SWType        byte
	SWSubType     byte
	SWMajorVer    byte
	SWMinorVer    byte
	SWStorageSize byte
	SWProtocol    byte
	UID           []byte
	BatchNo       []byte
	FabKey        byte
	ProdYear      byte
	ProdWeek      byte
}

func swOK(sw uint16) bool {
	return sw == 0x9000 || sw == 0x9100
}

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

func selectFile(card *scard.Card, fileID uint16) error {
	apdu := []byte{0x00, 0xA4, 0x00, 0x0C, 0x02, byte(fileID >> 8), byte(fileID)}
	_, sw, err := transmit(card, apdu)
	if err != nil {
		return err
	}
	if !swOK(sw) {
		return fmt.Errorf("SELECT FILE 0x%04X failed (SW1SW2=%04X)", fileID, sw)
	}
	return nil
}

func readBinary(card *scard.Card, offset uint16, le byte) ([]byte, error) {
	apdu := []byte{0x00, 0xB0, byte(offset >> 8), byte(offset), le}
	data, sw, err := transmit(card, apdu)
	if err != nil {
		return nil, err
	}
	if (sw & 0xFF00) == 0x6C00 {
		apdu[4] = byte(sw & 0x00FF)
		data, sw, err = transmit(card, apdu)
		if err != nil {
			return nil, err
		}
	}
	if !swOK(sw) {
		return nil, fmt.Errorf("READ BINARY failed (SW1SW2=%04X)", sw)
	}
	return data, nil
}

func readNDEF(card *scard.Card) ([]byte, error) {
	if err := selectNDEFApp(card); err != nil {
		return nil, err
	}
	if err := selectFile(card, 0xE103); err != nil {
		return nil, err
	}
	cc, err := readBinary(card, 0x0000, 0x0F)
	if err != nil {
		return nil, err
	}
	if len(cc) < 15 {
		return nil, fmt.Errorf("CC file too short")
	}

	ndefFileID := uint16(0xE104)
	if cc[7] == 0x04 && cc[8] >= 6 {
		ndefFileID = uint16(cc[9])<<8 | uint16(cc[10])
	}

	if err := selectFile(card, ndefFileID); err != nil {
		return nil, err
	}
	nlenBytes, err := readBinary(card, 0x0000, 0x02)
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

	ndef := make([]byte, 0, nlen)
	offset := 2
	remaining := nlen
	for remaining > 0 {
		chunk := remaining
		if chunk > 0xFF {
			chunk = 0xFF
		}
		part, err := readBinary(card, uint16(offset), byte(chunk))
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

func getVersion(card *scard.Card) (*TagVersion, error) {
	// GetVersion is a three-part command exchange at PICC level
	// First part: 0x60
	apdu1 := []byte{0x90, 0x60, 0x00, 0x00, 0x00}
	resp1, sw, err := transmit(card, apdu1)
	if err != nil {
		return nil, err
	}
	if sw != 0x91AF || len(resp1) != 7 {
		return nil, fmt.Errorf("GetVersion part 1 failed (SW=%04X len=%d)", sw, len(resp1))
	}

	// Second part: 0xAF
	apdu2 := []byte{0x90, 0xAF, 0x00, 0x00, 0x00}
	resp2, sw, err := transmit(card, apdu2)
	if err != nil {
		return nil, err
	}
	if sw != 0x91AF || len(resp2) != 7 {
		return nil, fmt.Errorf("GetVersion part 2 failed (SW=%04X len=%d)", sw, len(resp2))
	}

	// Third part: 0xAF
	apdu3 := []byte{0x90, 0xAF, 0x00, 0x00, 0x00}
	resp3, sw, err := transmit(card, apdu3)
	if err != nil {
		return nil, err
	}
	if !swOK(sw) || len(resp3) != 14 {
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

func printTagVersion(v *TagVersion) {
	if v == nil {
		return
	}
	fmt.Println("Tag version:")
	fmt.Printf("  HW: vendor=%02X type=%02X subtype=%02X ver=%d.%d storage=%02X proto=%02X\n",
		v.HWVendorID, v.HWType, v.HWSubType, v.HWMajorVer, v.HWMinorVer, v.HWStorageSize, v.HWProtocol)
	fmt.Printf("  SW: vendor=%02X type=%02X subtype=%02X ver=%d.%d storage=%02X proto=%02X\n",
		v.SWVendorID, v.SWType, v.SWSubType, v.SWMajorVer, v.SWMinorVer, v.SWStorageSize, v.SWProtocol)
	fmt.Printf("  UID: %s\n", hexUpper(v.UID))
	fmt.Printf("  Batch: %s\n", hexUpper(v.BatchNo))
	fmt.Printf("  Fab key: %02X\n", v.FabKey)
	fmt.Printf("  Production: 20%X%d Week %d\n", v.ProdYear/10, v.ProdYear%10, v.ProdWeek)
}

func getApplicationIDs(card *scard.Card) ([][]byte, error) {
	// DESFire GetApplicationIDs command (0x6A) - no auth needed
	apdu := []byte{0x90, 0x6A, 0x00, 0x00, 0x00}
	data, sw, err := transmit(card, apdu)
	if err != nil {
		return nil, err
	}
	if !swOK(sw) {
		return nil, fmt.Errorf("GetApplicationIDs failed (SW1SW2=%04X)", sw)
	}

	// Parse response into 3-byte AID chunks
	if len(data)%3 != 0 {
		return nil, fmt.Errorf("invalid GetApplicationIDs response length: %d", len(data))
	}

	apps := make([][]byte, 0, len(data)/3)
	for i := 0; i < len(data); i += 3 {
		aid := make([]byte, 3)
		copy(aid, data[i:i+3])
		apps = append(apps, aid)
	}
	return apps, nil
}

func getFileIDs(card *scard.Card) ([]byte, error) {
	// DESFire GetFileIDs command (0x6F) - no auth needed
	apdu := []byte{0x90, 0x6F, 0x00, 0x00, 0x00}
	data, sw, err := transmit(card, apdu)
	if err != nil {
		return nil, err
	}
	if !swOK(sw) {
		return nil, fmt.Errorf("GetFileIDs failed (SW1SW2=%04X)", sw)
	}
	return data, nil
}

func printApplications(card *scard.Card, apps [][]byte) {
	fmt.Println("Applications:")
	if len(apps) == 0 {
		fmt.Println("  (none)")
		return
	}

	for _, aid := range apps {
		aidHex := hexUpper(aid)
		desc := ""
		// Check if it's the NDEF type 4 tag application
		if len(aid) == 3 && aid[0] == 0xD2 && aid[1] == 0x76 && aid[2] == 0x00 {
			desc = " (NDEF type 4 tag)"
		}
		fmt.Printf("  AID: %s%s\n", aidHex, desc)

		// Try to select this app and get its file IDs
		fullAID := []byte{aid[0], aid[1], aid[2], 0x00, 0x85, 0x01, 0x01}
		apdu := []byte{0x00, 0xA4, 0x04, 0x00, byte(len(fullAID))}
		apdu = append(apdu, fullAID...)
		apdu = append(apdu, 0x00)
		_, sw, err := transmit(card, apdu)
		if err == nil && swOK(sw) {
			fileIDs, err := getFileIDs(card)
			if err == nil && len(fileIDs) > 0 {
				fileList := make([]string, len(fileIDs))
				for i, fid := range fileIDs {
					fileList[i] = fmt.Sprintf("%02X", fid)
				}
				fmt.Printf("    Files: %s\n", strings.Join(fileList, ", "))
			}
		}
	}
}

func printKeySlots(card *scard.Card, cfg *readerConfig) {
	fmt.Println("Key slots:")

	// Prepare keys to test
	type keyInfo struct {
		key   []byte
		label string
	}

	keys := []keyInfo{
		{make([]byte, 16), "all-zero"},
	}

	// Add configured keys if available
	if cfg != nil {
		if len(cfg.authKey) == 16 {
			keys = append(keys, keyInfo{cfg.authKey, cfg.authKeyLabel})
		}
		if len(cfg.sdmKey) == 16 {
			keys = append(keys, keyInfo{cfg.sdmKey, cfg.sdmKeyLabel})
		}
	}

	// Load additional keys from key directories
	keyDirs := []string{"../keys"}
	for _, dir := range keyDirs {
		keyFiles, err := loadAllHexKeys(dir)
		if err == nil {
			for _, kf := range keyFiles {
				// Check if we already have this key
				isDuplicate := false
				for _, existing := range keys {
					if len(existing.key) == len(kf.key) && string(existing.key) == string(kf.key) {
						isDuplicate = true
						break
					}
				}
				if !isDuplicate {
					keys = append(keys, keyInfo{kf.key, kf.name})
				}
			}
		}
	}

	// Get key settings to determine change authority
	// Note: GetKeySettings may be restricted on some cards. If access is denied,
	// we won't be able to show which key can change each slot.
	var changeKeyNo byte = 0xFF // unknown
	if err := selectNDEFApp(card); err == nil {
		// Try plain GetKeySettings first
		if ks, _, err := getKeySettingsPlain(card); err == nil {
			changeKeyNo = (ks >> 4) & 0x0F
		} else {
			// Plain GetKeySettings failed - try with authentication
			// Try authenticating with key 0 (AppMasterKey)
			for _, k := range keys {
				if err := selectNDEFApp(card); err != nil {
					continue
				}
				sess, err := authenticateEV2First(card, k.key, 0)
				if err != nil {
					continue
				}
				if ks, _, err := getKeySettingsSecure(card, sess); err == nil {
					changeKeyNo = (ks >> 4) & 0x0F
					break
				}
			}
		}
	}

	// Test each slot (0-4 are standard on NTAG 424 DNA)
	slotRoles := map[byte]string{
		0: "AppMaster",
		1: "SDM",
		2: "File Two Write",
		3: "read/write",
		4: "read/write",
	}

	for slot := byte(0); slot <= 4; slot++ {
		role := slotRoles[slot]
		if role == "" {
			role = "unused"
		}

		// Try each key on this slot
		var matchedKey string
		for _, k := range keys {
			if err := selectNDEFApp(card); err != nil {
				continue
			}
			if _, err := authenticateEV2First(card, k.key, slot); err == nil {
				matchedKey = k.label
				break
			}
		}

		status := "unknown"
		if matchedKey != "" {
			if matchedKey == "all-zero" {
				status = "default (all-zero)"
			} else {
				status = fmt.Sprintf("provisioned (%s)", matchedKey)
			}
		}

		fmt.Printf("  Slot %d (%s): %s\n", slot, role, status)

		// Show which key can change this slot
		if changeKeyNo != 0xFF {
			var changeLabel string
			if slot == 0 {
				changeLabel = "Key slot 0 (self)"
			} else {
				switch changeKeyNo {
				case 0x0E:
					changeLabel = fmt.Sprintf("Key slot %d (self)", slot)
				case 0x0F:
					changeLabel = "frozen (cannot be changed)"
				default:
					changeLabel = fmt.Sprintf("Key slot %d", changeKeyNo)
					if role := slotRoles[changeKeyNo]; role != "" {
						changeLabel += fmt.Sprintf("       <- %s key", role)
					}
				}
			}
			fmt.Printf("    changeable by: %s\n", changeLabel)
		}
	}
}

func printFilesInfo(card *scard.Card, cfg *readerConfig) {
	fmt.Println("File settings:")

	// Select NDEF app
	if err := selectNDEFApp(card); err != nil {
		fmt.Printf("  Error: Could not select NDEF app: %v\n", err)
		return
	}

	// Define files to check
	fileInfos := []struct {
		fileNo byte
		name   string
	}{
		{0x01, "CC"},
		{0x02, "NDEF"},
		{0x03, "proprietary"},
	}

	for _, finfo := range fileInfos {
		fmt.Printf("  File %d (%s):\n", finfo.fileNo, finfo.name)

		// Try to get file settings (plain first, then authenticated if needed)
		fs, err := getFileSettingsPlain(card, finfo.fileNo)
		if err != nil {
			// Try authenticated read with available keys
			fs = tryGetFileSettingsAuth(card, finfo.fileNo, cfg)
			if fs == nil {
				fmt.Printf("    Error: Could not read file settings\n")
				continue
			}
		}

		// Parse file type
		fileTypeStr := "unknown"
		switch fs.fileType {
		case 0x00:
			fileTypeStr = "standard data"
		case 0x01:
			fileTypeStr = "backup data"
		case 0x02:
			fileTypeStr = "value"
		case 0x03:
			fileTypeStr = "linear record"
		case 0x04:
			fileTypeStr = "cyclic record"
		}

		// Parse access rights
		r := (fs.ar2 >> 4) & 0x0F
		w := fs.ar2 & 0x0F
		rw := (fs.ar1 >> 4) & 0x0F
		car := fs.ar1 & 0x0F

		// Parse comm mode
		commMode := fs.fileOption & 0x03
		commModeStr := "unknown"
		switch commMode {
		case 0:
			commModeStr = "plain"
		case 1:
			commModeStr = "MAC"
		case 3:
			commModeStr = "full encryption"
		}

		// Display file settings
		fmt.Printf("    Type:             %s (0x%02X)\n", fileTypeStr, fs.fileType)
		fmt.Printf("    Size:             %d bytes\n", fs.size)
		fmt.Printf("    Comm mode:        %s\n", commModeStr)
		fmt.Printf("    Read access:      %s\n", accessLabel(r, cfg))
		fmt.Printf("    Write access:     %s\n", accessLabel(w, cfg))
		fmt.Printf("    Read+Write:       %s\n", accessLabel(rw, cfg))
		fmt.Printf("    Change settings:  %s\n", accessLabel(car, cfg))

		// Check SDM status
		sdmEnabled := (fs.fileOption & 0x40) != 0
		if sdmEnabled {
			fmt.Printf("    SDM:              enabled\n")
			fmt.Printf("      MAC generation: %s\n", accessLabel(fs.sdmFile, cfg))
			fmt.Printf("      Counter read:   %s\n", accessLabel(fs.sdmCtr, cfg))
			fmt.Printf("      Meta read:      %s (UID/counter metadata)\n", accessLabel(fs.sdmMeta, cfg))

			// Decode SDM options byte
			var sdmFeatures []string
			if (fs.sdmOptions & 0x80) != 0 { // Bit 7: UID mirroring (FIXED)
				sdmFeatures = append(sdmFeatures, "UID mirror (embed unique ID in URL)")
			}
			if (fs.sdmOptions & 0x40) != 0 { // Bit 6: Counter mirroring (FIXED)
				sdmFeatures = append(sdmFeatures, "ReadCtr mirror (embed read count in URL)")
			}
			if (fs.sdmOptions & 0x20) != 0 { // Bit 5: ReadCtr limit (FIXED)
				sdmFeatures = append(sdmFeatures, "ReadCtr limit (enforce max reads)")
			}
			if (fs.sdmOptions & 0x10) != 0 { // Bit 4: ENC file data
				sdmFeatures = append(sdmFeatures, "ENC file data")
			}
			if (fs.sdmOptions & 0x01) != 0 { // Bit 0: Tag tamper status (FIXED)
				sdmFeatures = append(sdmFeatures, "TT status (tag tamper)")
			}

			if len(sdmFeatures) > 0 {
				fmt.Printf("      Options:        0x%02X (%s)\n", fs.sdmOptions, strings.Join(sdmFeatures, ", "))
			} else {
				fmt.Printf("      Options:        0x%02X\n", fs.sdmOptions)
			}
		} else {
			fmt.Printf("    SDM:              disabled\n")
		}
		fmt.Println()
	}
}

func tryGetFileSettingsAuth(card *scard.Card, fileNo byte, cfg *readerConfig) *fileSettings {
	// Try authenticating with known keys and reading file settings
	keys := []struct {
		key   []byte
		keyNo byte
	}{
		{make([]byte, 16), 0}, // all-zero with slot 0
	}

	if cfg != nil {
		if len(cfg.authKey) == 16 {
			keys = append(keys, struct {
				key   []byte
				keyNo byte
			}{cfg.authKey, cfg.authKeyNo})
		}
		if len(cfg.sdmKey) == 16 {
			keys = append(keys, struct {
				key   []byte
				keyNo byte
			}{cfg.sdmKey, cfg.sdmKeyNo})
		}
	}

	for _, k := range keys {
		if err := selectNDEFApp(card); err != nil {
			continue
		}
		sess, err := authenticateEV2First(card, k.key, k.keyNo)
		if err != nil {
			continue
		}
		fs, err := getFileSettingsSecure(card, sess, fileNo)
		if err == nil {
			return fs
		}
	}

	return nil
}

func readCCFile(card *scard.Card) ([]byte, error) {
	// Select NDEF application
	if err := selectNDEFApp(card); err != nil {
		return nil, err
	}

	// Select file 0xE103 (CC / Capability Container)
	if err := selectFile(card, 0xE103); err != nil {
		return nil, err
	}

	// Read CC file - typically 15-23 bytes, we'll read up to 32 to be safe
	data, err := readBinary(card, 0x0000, 0x20)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func printCCFile(data []byte) {
	fmt.Println("File 1 (CC):")
	if len(data) == 0 {
		fmt.Println("  (empty)")
		return
	}

	// Print raw hex
	fmt.Printf("  Raw:              %s\n", hexUpper(data))

	// Parse known fields
	if len(data) < 7 {
		fmt.Println("  (too short to parse)")
		return
	}

	// CCLEN (bytes 0-1, big-endian)
	ccLen := int(data[0])<<8 | int(data[1])
	fmt.Printf("  CCLEN:            %d bytes\n", ccLen)

	// Mapping version (byte 2) - upper nibble.lower nibble
	mapVer := data[2]
	fmt.Printf("  Mapping version:  %d.%d\n", mapVer>>4, mapVer&0x0F)

	// MLe (bytes 3-4, big-endian) - Max R-APDU data size
	mle := int(data[3])<<8 | int(data[4])
	fmt.Printf("  MLe:              %d\n", mle)

	// MLc (bytes 5-6, big-endian) - Max C-APDU data size
	mlc := int(data[5])<<8 | int(data[6])
	fmt.Printf("  MLc:              %d\n", mlc)

	// NDEF File Control TLV starts at byte 7
	if len(data) < 8 {
		return
	}

	// Tag (byte 7) should be 0x04 for NDEF File Control TLV
	if data[7] != 0x04 {
		fmt.Printf("  TLV tag:          %02X (expected 04)\n", data[7])
		return
	}

	// Length (byte 8)
	if len(data) < 9 {
		return
	}
	tlvLen := int(data[8])

	// Parse NDEF File Control TLV (need at least 6 bytes)
	if tlvLen < 6 || len(data) < 9+tlvLen {
		return
	}

	// NDEF File ID (bytes 9-10, big-endian)
	ndefFileID := int(data[9])<<8 | int(data[10])
	fmt.Printf("  NDEF File ID:     %04X\n", ndefFileID)

	// Max NDEF size (bytes 11-12, big-endian)
	maxNDEF := int(data[11])<<8 | int(data[12])
	fmt.Printf("  Max NDEF size:    %d\n", maxNDEF)

	// Read access (byte 13)
	readAccess := data[13]
	fmt.Printf("  Read access:      %02X", readAccess)
	if readAccess == 0x00 {
		fmt.Printf(" (granted)")
	}
	fmt.Println()

	// Write access (byte 14)
	writeAccess := data[14]
	fmt.Printf("  Write access:     %02X", writeAccess)
	if writeAccess == 0x00 {
		fmt.Printf(" (granted)")
	}
	fmt.Println()
}

func readFile3(card *scard.Card, cfg *readerConfig) ([]byte, *fileSettings, error) {
	// Select NDEF application
	if err := selectNDEFApp(card); err != nil {
		return nil, nil, err
	}

	// Try to get file settings without authentication first
	var fsPlain *fileSettings
	fsPlain, err := getFileSettingsPlain(card, 0x03)
	if err == nil && fsPlain != nil {
		fmt.Printf("  File 3 settings (plain): size=%d, fileType=0x%02X, ar1=0x%02X, ar2=0x%02X\n",
			fsPlain.size, fsPlain.fileType, fsPlain.ar1, fsPlain.ar2)

		// If size is 0, file is empty
		if fsPlain.size == 0 {
			fmt.Println("  File 3 is empty (size=0)")
			return []byte{}, fsPlain, nil
		}
	} else {
		fmt.Printf("  Could not read file settings (plain): %v\n", err)
	}

	// Try unauthenticated read first
	const fileNo = 0x03
	fmt.Println("  Trying unauthenticated read...")
	lengths := []int{1, 8, 16, 32, 128}
	for _, length := range lengths {
		apdu := []byte{0x90, 0xBD, 0x00, 0x00, 0x07,
			fileNo,
			0x00, 0x00, 0x00, // offset: 0
			byte(length), byte(length >> 8), byte(length >> 16), // length
			0x00}
		data, sw, err := transmit(card, apdu)
		if err == nil && swOK(sw) {
			fmt.Printf("  Unauthenticated read succeeded: %d bytes\n", len(data))
			if fsPlain == nil {
				fsPlain = &fileSettings{size: len(data)}
			}
			return data, fsPlain, nil
		}
		// If auth required, break and try with authentication
		if sw == 0x6982 {
			fmt.Println("  Authentication required")
			break
		}
	}

	// Build list of key attempts: (key, keyNo, label)
	type keyAttempt struct {
		key   []byte
		keyNo byte
		label string
	}

	attempts := []keyAttempt{}

	// Try all-zero key with all key slots (factory default for NTAG 424 DNA)
	allZeroKey := make([]byte, 16)
	for keyNo := byte(0); keyNo < 16; keyNo++ {
		attempts = append(attempts, keyAttempt{allZeroKey, keyNo, fmt.Sprintf("all-zero/KeyNo %d", keyNo)})
	}

	// Load all .hex keys from multiple directories
	keyDirs := []string{"../keys"}
	for _, dir := range keyDirs {
		keyFiles, err := loadAllHexKeys(dir)
		if err != nil {
			continue
		}
		// Try each loaded key with all key slots
		for _, kf := range keyFiles {
			for keyNo := byte(0); keyNo < 16; keyNo++ {
				attempts = append(attempts, keyAttempt{kf.key, keyNo, fmt.Sprintf("%s/KeyNo %d", kf.name, keyNo)})
			}
		}
	}

	// Try each key combination
	fmt.Println("  Attempting authentication for File 3...")
	var lastAuthErr error
	for _, attempt := range attempts {
		// Re-select app for fresh auth attempt
		if err := selectNDEFApp(card); err != nil {
			continue
		}

		sess, err := authenticateEV2First(card, attempt.key, attempt.keyNo)
		if err != nil {
			lastAuthErr = err
			continue // Try next key
		}

		// Auth succeeded
		fmt.Printf("  Auth succeeded with %s\n", attempt.label)

		// Determine read length: use fsPlain.size if available, otherwise try common lengths
		const fileNo = 0x03
		var data []byte
		var readErr error

		if fsPlain != nil && fsPlain.size > 0 {
			// We know the allocated size from plain file settings, but the file might be empty
			// Try reading the allocated size first
			readDataCmd := []byte{
				fileNo,
				0x00, 0x00, 0x00, // offset: 0
				byte(fsPlain.size), byte(fsPlain.size >> 8), byte(fsPlain.size >> 16),
			}
			data, readErr = ssmCmdFull(card, sess, 0xBD, nil, readDataCmd)
			if readErr == nil {
				fmt.Printf("  Successfully read %d bytes\n", len(data))
				return data, fsPlain, nil
			}

			// Check if it's a boundary error (SW=911C) - means file is empty or contains less data
			if ntag424.IsBoundaryError(readErr) {
				fmt.Printf("  File has size %d but contains no data (empty)\n", fsPlain.size)
				return []byte{}, fsPlain, nil
			}
			fmt.Printf("  DESFire ReadData failed: %v\n", readErr)
		} else if fsPlain != nil && fsPlain.size == 0 {
			// File size is 0, return empty
			fmt.Println("  File 3 has size 0 (empty)")
			return []byte{}, fsPlain, nil
		} else {
			// Try common lengths since we don't know the size
			lengths := []int{128, 32, 16, 8, 1}
			for _, length := range lengths {
				readDataCmd := []byte{
					fileNo,
					0x00, 0x00, 0x00, // offset: 0
					byte(length), byte(length >> 8), byte(length >> 16),
				}
				data, readErr = ssmCmdFull(card, sess, 0xBD, nil, readDataCmd)
				if readErr == nil {
					fmt.Printf("  Successfully read %d bytes (size unknown, tried length %d)\n", len(data), length)
					// Build a minimal fileSettings if we don't have one
					fs := fsPlain
					if fs == nil {
						fs = &fileSettings{size: len(data)}
					}
					return data, fs, nil
				}
			}
			fmt.Printf("  DESFire ReadData failed for all attempted lengths: %v\n", readErr)
		}
	}

	// If we got plain file settings but couldn't read data, return what we have
	if fsPlain != nil {
		return []byte{}, fsPlain, fmt.Errorf("could not read data (last auth error: %v)", lastAuthErr)
	}

	return nil, nil, fmt.Errorf("authentication failed with all available keys and slots (last error: %v)", lastAuthErr)
}

func printFile3(data []byte, fs *fileSettings, cfg *readerConfig) {
	fmt.Println("File 3 (proprietary):")

	if fs != nil {
		// Display metadata
		fmt.Printf("  Size:         %d bytes", fs.size)
		if len(data) == 0 && fs.size > 0 {
			fmt.Printf(" (%d used)", fs.size)
		}
		fmt.Println()

		// Display communication mode
		commMode := fs.fileOption & 0x03
		commModeStr := "unknown"
		switch commMode {
		case 0:
			commModeStr = "plain"
		case 1:
			commModeStr = "MAC"
		case 3:
			commModeStr = "full"
		}
		fmt.Printf("  Comm mode:    %s\n", commModeStr)

		// Display access rights
		r := (fs.ar2 >> 4) & 0x0F
		w := fs.ar2 & 0x0F
		fmt.Printf("  Read access:  %s\n", accessLabel(r, cfg))
		fmt.Printf("  Write access: %s\n", accessLabel(w, cfg))
	}

	// Display raw data
	if len(data) == 0 {
		fmt.Println("  Raw:          (empty)")
	} else {
		fmt.Printf("  Raw:          %s\n", hexUpper(data))
	}
}
