package main

import (
	"unsafe"

	"github.com/ebfe/scard"
	"github.com/barnettlynn/nfctools/pkg/ntag424"
)

// Type definitions matching local usage
type sdmNDEF struct {
	url            string
	ndef           []byte
	uidOffset      uint32
	ctrOffset      uint32
	macInputOffset uint32
	macOffset      uint32
}

type session struct {
	kenc   [16]byte
	kmac   [16]byte
	ti     [4]byte
	cmdCtr uint16
}

// Session conversion helpers (identical memory layout allows unsafe conversion)
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

func changeKey(card *scard.Card, sess *session, keyNo byte, oldKey, newKey []byte, keyVer byte) error {
	// newekey uses different parameter order than shared library
	// newekey: changeKey(card, sess, keyNo, oldKey, newKey, keyVer)
	// ntag424: ChangeKey(card, sess, keySlot, newKey, oldKey, keyVersion, authSlot, debug)
	// For newekey, authSlot is always 0 (authenticated with KeyNo 0)
	return ntag424.ChangeKey(card, toNtag424Session(sess), keyNo, newKey, oldKey, keyVer, 0)
}

func buildSDMNDEF(baseURL string) (*sdmNDEF, error) {
	sdm, err := ntag424.BuildSDMNDEF(baseURL)
	if err != nil {
		return nil, err
	}
	return &sdmNDEF{
		url:            sdm.URL,
		ndef:           sdm.NDEF,
		uidOffset:      sdm.UIDOffset,
		ctrOffset:      sdm.CtrOffset,
		macInputOffset: sdm.MacInputOffset,
		macOffset:      sdm.MacOffset,
	}, nil
}

func changeFileSettingsSDM(card *scard.Card, sess *session, fileNo byte, commMode byte, ar1, ar2 byte,
	sdmOptions, sdmMeta, sdmFile, sdmCtr byte,
	uidOffset, ctrOffset, macInputOffset, macOffset uint32) error {
	return ntag424.ChangeFileSettingsSDM(card, toNtag424Session(sess), fileNo, commMode, ar1, ar2,
		sdmOptions, sdmMeta, sdmFile, sdmCtr, uidOffset, ctrOffset, macInputOffset, macOffset)
}

func writeNDEFPlain(card *scard.Card, data []byte) error {
	return ntag424.WriteNDEFPlain(card, data)
}
