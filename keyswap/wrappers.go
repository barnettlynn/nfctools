package main

import (
	"encoding/hex"
	"strings"
	"unsafe"

	"github.com/ebfe/scard"
	"github.com/barnettlynn/nfctools/pkg/ntag424"
)

// Type definitions
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

// Session conversion helpers
func toNtag424Session(s *session) *ntag424.Session {
	if s == nil {
		return nil
	}
	return (*ntag424.Session)(unsafe.Pointer(s))
}

func fromNtag424Session(s *ntag424.Session) *session {
	if s == nil {
		return nil
	}
	return (*session)(unsafe.Pointer(s))
}

// Wrapper functions
func getUID(card *scard.Card) ([]byte, error) {
	return ntag424.GetUID(card)
}

func selectNDEFApp(card *scard.Card) error {
	return ntag424.SelectNDEFApp(card)
}

func transmit(card *scard.Card, apdu []byte) ([]byte, uint16, error) {
	return ntag424.Transmit(card, apdu)
}

func swOK(sw uint16) bool {
	return ntag424.SwOK(sw)
}

func authenticateEV2First(card *scard.Card, key []byte, keyNo byte) (*session, error) {
	sess, err := ntag424.AuthenticateEV2First(card, key, keyNo)
	if err != nil {
		return nil, err
	}
	return fromNtag424Session(sess), nil
}

func changeKey(card *scard.Card, sess *session, keySlot byte, newKey, oldKey []byte, keyVersion byte, authSlot byte) error {
	return ntag424.ChangeKey(card, toNtag424Session(sess), keySlot, newKey, oldKey, keyVersion, authSlot)
}

func changeKeySame(card *scard.Card, sess *session, keySlot byte, newKey []byte, keyVersion byte) error {
	return ntag424.ChangeKeySame(card, toNtag424Session(sess), keySlot, newKey, keyVersion)
}

func crc32DESFire(data []byte) uint32 {
	return ntag424.CRC32DESFire(data)
}

func loadKeyHexFile(path string) ([]byte, error) {
	return ntag424.LoadKeyHexFile(path)
}

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

func getKeySettings(card *scard.Card, sess *session) (keySettings byte, maxKeys byte, err error) {
	// For now use a simple plain APDU - can enhance later
	apdu := []byte{0x90, 0x45, 0x00, 0x00, 0x00}
	resp, sw, err := transmit(card, apdu)
	if err != nil {
		return 0, 0, err
	}
	if !swOK(sw) || len(resp) < 2 {
		return 0, 0, err
	}
	return resp[0], resp[1], nil
}

func hexUpper(b []byte) string {
	return strings.ToUpper(hex.EncodeToString(b))
}
