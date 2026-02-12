package main

import (
	"bufio"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/ebfe/scard"
	"golang.org/x/term"
)

// ============================================================================
// Types
// ============================================================================

type probeResult struct {
	key   []byte
	label string
}

// ============================================================================
// Card I/O
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

	fmt.Println("=== NTAG 424 DNA Key Swap Tool ===")
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

	// Probe all key slots
	fmt.Println("Probing key slots...")

	// Load all available keys
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

	// Probe each slot
	slotKeys := make(map[byte]probeResult)
	slotRoles := map[byte]string{
		0: "AppMaster",
		1: "SDM",
		2: "File Two Write",
		3: "read/write",
		4: "read/write",
	}

	for slot := byte(0); slot <= 4; slot++ {
		for _, k := range keys {
			if err := selectNDEFApp(card); err != nil {
				continue
			}
			if _, err := authenticateEV2First(card, k.key, slot); err == nil {
				slotKeys[slot] = probeResult{key: k.key, label: k.label}
				break
			}
		}
	}

	// Display slot status
	fmt.Println()
	fmt.Println("Key slot status:")
	fmt.Println("Slot | Role        | Status")
	fmt.Println("-----|-------------|---------------------------")
	for slot := byte(0); slot <= 4; slot++ {
		role := slotRoles[slot]
		status := "unknown"
		if result, ok := slotKeys[slot]; ok {
			if result.label == "all-zero" {
				status = "default (all-zero)"
			} else {
				status = fmt.Sprintf("provisioned (%s)", result.label)
			}
		}
		fmt.Printf("  %d  | %-11s | %s\n", slot, role, status)
	}
	fmt.Println()

	// Prompt for slot selection using arrow keys
	slotItems := []string{}
	slotOrder := []byte{0, 1, 2, 3, 4}
	for _, slot := range slotOrder {
		role := slotRoles[slot]
		status := "unknown"
		if result, ok := slotKeys[slot]; ok {
			if result.label == "all-zero" {
				status = "default (all-zero)"
			} else {
				status = fmt.Sprintf("provisioned (%s)", result.label)
			}
		}
		slotItems = append(slotItems, fmt.Sprintf("%d - %-11s [%s]", slot, role, status))
	}

	selectedIdx := selectMenu("Select slot to change:", slotItems)
	if selectedIdx < 0 {
		fmt.Println("Invalid selection.")
		os.Exit(1)
	}
	targetSlot := slotOrder[selectedIdx]

	// Check if we know the current key for this slot
	currentKey, ok := slotKeys[targetSlot]
	if !ok {
		fmt.Printf("Error: Current key for slot %d is unknown. Cannot proceed.\n", targetSlot)
		os.Exit(1)
	}

	// If changing slots 1-4, we need to know slot 0's key
	var authSlot byte
	var authKey []byte
	if targetSlot == 0 {
		authSlot = 0
		authKey = currentKey.key
	} else {
		authSlot = 0
		slot0Key, ok := slotKeys[0]
		if !ok {
			fmt.Printf("Error: Slot 0 key is unknown. Cannot change slots 1-4.\n")
			os.Exit(1)
		}
		authKey = slot0Key.key
	}

	// Load and display available key files
	fmt.Println()

	// Build combined key list: all-zero option + key files
	type keyChoice struct {
		name string
		key  []byte
	}
	allKeys := []keyChoice{
		{name: "all-zero (default)", key: make([]byte, 16)},
	}
	for _, kf := range keyFiles {
		allKeys = append(allKeys, keyChoice{name: kf.name, key: kf.key})
	}

	// Build menu items
	keyItems := []string{}
	for _, k := range allKeys {
		keyItems = append(keyItems, k.name)
	}

	// Prompt for new key selection using arrow keys
	newKeyIdx := selectMenu("Select new key:", keyItems)
	if newKeyIdx < 0 {
		fmt.Println("Invalid selection.")
		os.Exit(1)
	}

	newKey := allKeys[newKeyIdx].key
	newKeyLabel := allKeys[newKeyIdx].name

	// Confirm
	fmt.Println()
	fmt.Printf("Replace slot %d key with %s? (y/n): ", targetSlot, newKeyLabel)
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

	// Perform key change
	fmt.Println()
	fmt.Println("Changing key...")

	if err := selectNDEFApp(card); err != nil {
		fmt.Printf("Error re-selecting NDEF app: %v\n", err)
		os.Exit(1)
	}

	sess, err := authenticateEV2First(card, authKey, authSlot)
	if err != nil {
		fmt.Printf("Authentication failed: %v\n", err)
		os.Exit(1)
	}

	if targetSlot == 0 {
		// Slot 0: Use changeKeySame (same-key change)
		err = changeKeySame(card, sess, targetSlot, newKey, 0x00)
	} else {
		// Slots 1-4: Use changeKey (different-key change)
		err = changeKey(card, sess, targetSlot, newKey, currentKey.key, 0x00, authSlot)
	}

	if err != nil {
		fmt.Printf("Key change failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Key change successful!")

	// Verify by re-authenticating with the new key
	fmt.Println("Verifying...")
	if err := selectNDEFApp(card); err != nil {
		fmt.Printf("Error re-selecting NDEF app: %v\n", err)
		os.Exit(1)
	}

	_, err = authenticateEV2First(card, newKey, targetSlot)
	if err != nil {
		fmt.Printf("Verification failed: Cannot authenticate with new key: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Printf("SUCCESS: Slot %d key replaced with %s\n", targetSlot, newKeyLabel)
	fmt.Printf("Authenticated with: slot %d (%s)\n", authSlot, slotKeys[authSlot].label)
}
