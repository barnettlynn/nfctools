package ntag424

// AuthSlotResult holds the result of an authentication attempt for diagnostics.
type AuthSlotResult struct {
	Slot    byte   // Key slot number
	Success bool   // True if authentication succeeded
	Step    string // Authentication step where failure occurred ("step1" or "step2")
	SW      uint16 // Status word from failed step
	RespLen int    // Response length from failed step
	Err     error  // Underlying error
}

// DiagnoseAuthSlots attempts authentication with a key on multiple slots.
// This is useful for diagnosing key slot configuration issues.
// From update/internal/ntag/diag.go.
//
// Parameters:
//   - card: Card interface
//   - key: 16-byte AES key to test
//   - slots: List of slot numbers to test (typically 0-15)
//
// Returns:
//   - Slice of AuthSlotResult, one per slot tested
//
// Note: This function does NOT call SelectNDEFApp between attempts.
// The caller should select the app once before calling this function.
func DiagnoseAuthSlots(card Card, key []byte, slots []byte) []AuthSlotResult {
	results := make([]AuthSlotResult, 0, len(slots))
	for _, slot := range slots {
		_, err := AuthenticateEV2First(card, key, slot)
		result := AuthSlotResult{Slot: slot, Success: err == nil, Err: err}
		if err != nil {
			step, sw, respLen, ok := ClassifyAuthError(err)
			if ok {
				result.Step = step
				result.SW = sw
				result.RespLen = respLen
			}
		}
		results = append(results, result)
	}
	return results
}
