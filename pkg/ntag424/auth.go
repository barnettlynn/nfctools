package ntag424

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// Session holds the encryption and MAC keys for an authenticated session.
type Session struct {
	kenc   [16]byte
	kmac   [16]byte
	ti     [4]byte
	cmdCtr uint16
}

// AuthError represents an authentication failure at a specific step.
type AuthError struct {
	Step    string // "step1" or "step2"
	SW      uint16 // Status word (if applicable)
	RespLen int    // Response length (if applicable)
	Cause   error  // Underlying error
}

func (e *AuthError) Error() string {
	if e == nil {
		return "auth error"
	}
	if e.Cause != nil {
		return fmt.Sprintf("auth %s failed: %v", e.Step, e.Cause)
	}
	return fmt.Sprintf("auth %s failed (SW=%04X len=%d)", e.Step, e.SW, e.RespLen)
}

func (e *AuthError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// ClassifyAuthError extracts details from an AuthError.
func ClassifyAuthError(err error) (step string, sw uint16, respLen int, ok bool) {
	var authErr *AuthError
	if errors.As(err, &authErr) {
		return authErr.Step, authErr.SW, authErr.RespLen, true
	}
	return "", 0, 0, false
}

// AuthenticateEV2First performs EV2First authentication with the card.
// This is a two-phase challenge-response handshake that establishes
// session keys Kenc and Kmac for subsequent secure messaging.
//
// Environment variables for testing:
//   - NTAG_RNDA: 32-character hex string to override random RndA generation
func AuthenticateEV2First(card Card, key []byte, keyNo byte) (*Session, error) {
	// Phase 1: Send keyNo, receive encrypted RndB
	apdu1 := []byte{0x90, 0x71, 0x00, 0x00, 0x02, keyNo, 0x00, 0x00}
	resp1, sw, err := Transmit(card, apdu1)
	if err != nil {
		return nil, &AuthError{Step: "step1", Cause: err}
	}
	if sw != SWMoreData || len(resp1) != 16 {
		return nil, &AuthError{Step: "step1", SW: sw, RespLen: len(resp1)}
	}

	iv0 := make([]byte, 16)
	rndB, err := aesCBCDecrypt(key, iv0, resp1)
	if err != nil {
		return nil, &AuthError{Step: "step1", Cause: err}
	}

	// Generate RndA (or use env override for deterministic testing)
	rndA := make([]byte, 16)
	if rndAHex := os.Getenv("NTAG_RNDA"); len(rndAHex) == 32 {
		if b, err := hex.DecodeString(rndAHex); err == nil && len(b) == 16 {
			copy(rndA, b)
		} else if _, err := io.ReadFull(rand.Reader, rndA); err != nil {
			return nil, &AuthError{Step: "step1", Cause: err}
		}
	} else if _, err := io.ReadFull(rand.Reader, rndA); err != nil {
		return nil, &AuthError{Step: "step1", Cause: err}
	}

	// Phase 2: Send encrypted RndA||RndB', receive encrypted TI||RndA'
	rndBRot := rotateLeft1(rndB)
	rndAB := append(append([]byte{}, rndA...), rndBRot...)
	rndABEnc, err := aesCBCEncrypt(key, iv0, rndAB)
	if err != nil {
		return nil, &AuthError{Step: "step2", Cause: err}
	}

	apdu2 := make([]byte, 0, 5+len(rndABEnc)+1)
	apdu2 = append(apdu2, 0x90, 0xAF, 0x00, 0x00, 0x20)
	apdu2 = append(apdu2, rndABEnc...)
	apdu2 = append(apdu2, 0x00)
	resp2, sw, err := Transmit(card, apdu2)
	if err != nil {
		return nil, &AuthError{Step: "step2", Cause: err}
	}
	if sw != SWDESFireOK || len(resp2) != 32 {
		return nil, &AuthError{Step: "step2", SW: sw, RespLen: len(resp2)}
	}

	// Verify RndA
	dec, err := aesCBCDecrypt(key, iv0, resp2)
	if err != nil {
		return nil, &AuthError{Step: "step2", Cause: err}
	}

	ti := dec[:4]
	rndARot := dec[4:20]
	rndACheck := rotateRight1(rndARot)
	if !bytes.Equal(rndACheck, rndA) {
		return nil, &AuthError{Step: "step2", Cause: errors.New("rndA check failed")}
	}

	// Derive session keys Kenc and Kmac
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
		return nil, &AuthError{Step: "step2", Cause: err}
	}
	kmac, err := aesCMAC(key, sv2)
	if err != nil {
		return nil, &AuthError{Step: "step2", Cause: err}
	}

	slog.Debug("session keys derived",
		"rndA", strings.ToUpper(hex.EncodeToString(rndA)),
		"rndB", strings.ToUpper(hex.EncodeToString(rndB)),
		"ti", strings.ToUpper(hex.EncodeToString(ti)),
		"kenc", strings.ToUpper(hex.EncodeToString(kenc)),
		"kmac", strings.ToUpper(hex.EncodeToString(kmac)))

	s := &Session{}
	copy(s.kenc[:], kenc)
	copy(s.kmac[:], kmac)
	copy(s.ti[:], ti)
	s.cmdCtr = 0
	return s, nil
}

// AuthenticateWithFallback attempts authentication with multiple key/slot combinations.
// It tries:
//   1. Provided key with keyNo
//   2. Provided key with altKeyNo (if different)
//   3. Provided key with slot 0 (if neither keyNo nor altKeyNo is 0)
//   4. All-zero key with slot 0 (if provided key is not all-zero)
//
// Returns (session, effective_key, effective_keyNo, error).
func AuthenticateWithFallback(card Card, key []byte, keyNo byte, altKeyNo byte) (*Session, []byte, byte, error) {
	zeroKey := make([]byte, 16)
	attempts := []struct {
		key   []byte
		keyNo byte
		label string
	}{
		{key: key, keyNo: keyNo, label: fmt.Sprintf("keyno %d (provided)", keyNo)},
	}

	if altKeyNo != keyNo {
		attempts = append(attempts, struct {
			key   []byte
			keyNo byte
			label string
		}{key: key, keyNo: altKeyNo, label: fmt.Sprintf("keyno %d (sdm-keyno)", altKeyNo)})
	}
	if keyNo != 0 && altKeyNo != 0 {
		attempts = append(attempts, struct {
			key   []byte
			keyNo byte
			label string
		}{key: key, keyNo: 0, label: "keyno 0 (same key)"})
	}
	if !isAllZero(key) {
		attempts = append(attempts, struct {
			key   []byte
			keyNo byte
			label string
		}{key: zeroKey, keyNo: 0, label: "keyno 0 (all-zero fallback)"})
	}

	var lastErr error
	for i, attempt := range attempts {
		sess, err := AuthenticateEV2First(card, attempt.key, attempt.keyNo)
		if err == nil {
			slog.Info("authenticated", "method", attempt.label)
			return sess, attempt.key, attempt.keyNo, nil
		}
		if i > 0 {
			slog.Warn("auth attempt failed", "method", attempt.label, "error", err)
		}
		lastErr = err
	}

	return nil, nil, 0, lastErr
}

func isAllZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
