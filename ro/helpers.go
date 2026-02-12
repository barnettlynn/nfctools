package main

import (
	"encoding/hex"
	"fmt"
	"strings"
)

func hexUpper(b []byte) string {
	return strings.ToUpper(hex.EncodeToString(b))
}

func okX(ok bool) string {
	if ok {
		return "OK"
	}
	return "X"
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func keyNoLabel(n byte) string {
	switch n {
	case 0x0E:
		return "E (free)"
	case 0x0F:
		return "F (no access)"
	default:
		return fmt.Sprintf("%X", n)
	}
}

func joinKeyNos(list []byte) string {
	if len(list) == 0 {
		return ""
	}
	parts := make([]string, 0, len(list))
	for _, v := range list {
		parts = append(parts, fmt.Sprintf("%X", v))
	}
	return strings.Join(parts, ",")
}
