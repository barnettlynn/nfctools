package main

import (
	"github.com/barnettlynn/nfctools/pkg/ntag424"
	"unsafe"
)

type readerConfig struct {
	authKey      []byte
	authKeyNo    byte
	authKeyLabel string
	sdmKey       []byte
	sdmKeyLabel  string
	sdmKeyNo     byte
	ndefKeyLabel string
	ndefKeyNo    byte
	fileNo       byte
	fullProbe    bool
}

type session struct {
	kenc   [16]byte
	kmac   [16]byte
	ti     [4]byte
	cmdCtr uint16
}

type fileSettings struct {
	fileType   byte
	fileOption byte
	ar1        byte
	ar2        byte
	size       int
	sdmOptions byte
	sdmMeta    byte
	sdmFile    byte
	sdmCtr     byte
}

type keyFile struct {
	name string
	key  []byte
}

// Session conversion helpers
// Note: session and ntag424.Session have identical memory layout,
// so we can use unsafe pointer conversion
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
