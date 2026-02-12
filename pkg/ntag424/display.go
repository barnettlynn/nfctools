package ntag424

import "fmt"

// accessLabel returns a human-readable label for an access rights nibble.
// From update/internal/ntag/types.go:45-54.
func accessLabel(keyNo byte) string {
	switch keyNo {
	case 0x0E:
		return "free            (no key needed)"
	case 0x0F:
		return "denied          (never)"
	default:
		return fmt.Sprintf("Key slot %d", keyNo)
	}
}

// PrintFileSettings prints file settings in a human-readable format.
// From update/internal/ntag/types.go:56-76.
//
// Parameters:
//   - label: Descriptive label (e.g., "BEFORE", "AFTER")
//   - fileNo: File number (0x01, 0x02, 0x03)
//   - fs: FileSettings structure
func PrintFileSettings(label string, fileNo byte, fs *FileSettings) {
	// Extract access rights from AR1/AR2
	readKey := (fs.AR2 >> 4) & 0x0F   // AR2 upper = Read
	writeKey := fs.AR2 & 0x0F          // AR2 lower = Write
	rwKey := (fs.AR1 >> 4) & 0x0F      // AR1 upper = ReadWrite
	changeKey := fs.AR1 & 0x0F         // AR1 lower = ChangeAccessRights

	fmt.Printf("  %s - File %d access rights:    [raw: %02X %02X]\n", label, fileNo, fs.AR1, fs.AR2)
	fmt.Printf("    Read data:        %s\n", accessLabel(readKey))
	fmt.Printf("    Write data:       %s\n", accessLabel(writeKey))
	fmt.Printf("    Read+Write:       %s\n", accessLabel(rwKey))
	fmt.Printf("    Change settings:  %s\n", accessLabel(changeKey))

	// Print SDM configuration if enabled
	if (fs.FileOption & 0x40) != 0 {
		fmt.Printf("  SDM config:                         [enabled, opts 0x%02X]\n", fs.SDMOptions)
		fmt.Printf("    MAC generation:   %s\n", accessLabel(fs.SDMFile))
		fmt.Printf("    Counter read:     %s\n", accessLabel(fs.SDMCtr))
		fmt.Printf("    Meta read:        %s\n", accessLabel(fs.SDMMeta))
	} else {
		fmt.Println("  SDM config:                         [disabled]")
	}
}
