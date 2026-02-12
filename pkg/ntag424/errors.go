package ntag424

import "fmt"

// Status word constants for ISO 7816 and DESFire responses
const (
	// ISO 7816 status words
	SWSuccess              = 0x9000 // ISO success
	SWSecurityNotSatisfied = 0x6982 // Security status not satisfied (need auth)
	SWFileNotFound         = 0x6A82 // File not found
	SWWrongP1P2            = 0x6A86 // Incorrect P1/P2 parameters
	SWWrongLength          = 0x6700 // Wrong length
	SWWrongLe              = 0x6C00 // Wrong Le (mask: 0x6C00, correct Le in SW2)

	// DESFire status words
	SWDESFireOK     = 0x9100 // DESFire success (operation complete)
	SWMoreData      = 0x91AF // Additional frame expected
	SWLengthError   = 0x917E // Length error (wrong Le, bad fileNo, or format error)
	SWAuthError     = 0x91AE // Authentication error (wrong key for slot)
	SWPermDenied    = 0x919D // Permission denied (authenticated but insufficient rights)
	SWParameterErr  = 0x919E // Parameter error (invalid settings data)
	SWBoundaryError = 0x911C // Command not allowed / boundary error (read past file end)
	SWNoChanges     = 0x9140 // No changes (settings already match)
	SWCommandAbort  = 0x91CA // Command aborted (general failure)
)

// SWError represents a status word error from the card.
type SWError struct {
	Cmd byte   // Command INS byte
	SW  uint16 // Status word
}

func (e *SWError) Error() string {
	return fmt.Sprintf("card command 0x%02X failed with SW=0x%04X (%s)", e.Cmd, e.SW, swDescription(e.SW))
}

// swDescription returns a human-readable description of a status word.
func swDescription(sw uint16) string {
	switch sw {
	case SWSuccess:
		return "success"
	case SWDESFireOK:
		return "DESFire OK"
	case SWMoreData:
		return "more data expected"
	case SWLengthError:
		return "length error"
	case SWAuthError:
		return "authentication error"
	case SWPermDenied:
		return "permission denied"
	case SWParameterErr:
		return "parameter error"
	case SWBoundaryError:
		return "boundary error"
	case SWNoChanges:
		return "no changes"
	case SWCommandAbort:
		return "command aborted"
	case SWSecurityNotSatisfied:
		return "security not satisfied"
	case SWFileNotFound:
		return "file not found"
	case SWWrongP1P2:
		return "wrong P1/P2"
	case SWWrongLength:
		return "wrong length"
	default:
		if (sw & 0xFF00) == SWWrongLe {
			return fmt.Sprintf("wrong Le (correct Le=%d)", sw&0xFF)
		}
		return "unknown error"
	}
}

// IsLengthError checks if an error is a length-related status word error.
func IsLengthError(err error) bool {
	if swErr, ok := err.(*SWError); ok {
		return swErr.SW == SWLengthError || swErr.SW == SWWrongLength || (swErr.SW&0xFF00) == SWWrongLe
	}
	return false
}

// IsAuthError checks if an error is an authentication-related status word error.
func IsAuthError(err error) bool {
	if swErr, ok := err.(*SWError); ok {
		return swErr.SW == SWAuthError || swErr.SW == SWSecurityNotSatisfied
	}
	return false
}

// IsBoundaryError checks if an error is a boundary error (read past file end).
func IsBoundaryError(err error) bool {
	if swErr, ok := err.(*SWError); ok {
		return swErr.SW == SWBoundaryError
	}
	return false
}

// IsPermissionDenied checks if an error is a permission denied error.
func IsPermissionDenied(err error) bool {
	if swErr, ok := err.(*SWError); ok {
		return swErr.SW == SWPermDenied
	}
	return false
}

// SwOK checks if a status word indicates success (ISO 9000 or DESFire 9100).
func SwOK(sw uint16) bool {
	return sw == SWSuccess || sw == SWDESFireOK
}
