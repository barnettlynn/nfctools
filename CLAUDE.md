# NFC Tools - NTAG 424 DNA Development Notes

## Key Discoveries

### NDEF Write Methods
- **Use ISO-level NDEF writes (`WriteNDEFPlain`)** instead of DESFire native file writes (`WriteFileDataPlain`) for NDEF data
- ISO writes via file 0x01 (NDEF app file) are more reliable than direct DESFire file writes to file 0x02
- DESFire writes may fail due to access rights even when authenticated

### Session Management
- **Changing key slot 0 invalidates the current session** - requires re-authentication after
- Cross-slot key changes (e.g., using slot 0 auth to change slot 1) preserve the session
- Same-slot changes (e.g., using slot 0 auth to change slot 0) invalidate the session
- Always re-select application and re-authenticate after changing slot 0

### Factory Reset Requirements
All 5 key slots (0-4) must be explicitly reset to 16 zero bytes with version 0x00:
- Slot 0: App master key
- Slot 1: SDM key (used by minter)
- Slot 2: NDEF write key (used by minter)
- Slot 3: Unused (but must still be reset)
- Slot 4: Unused (but must still be reset)

All 3 files must be restored to factory defaults:
- **File 1 (CC)**: FileOption=0x00, AR1=0x00, AR2=0xE0
- **File 2 (NDEF)**: FileOption=0x00, AR1=0x00, AR2=0xEE
- **File 3 (Proprietary)**: FileOption=0x03, AR1=0x00, AR2=0x00

AR2 encoding: `0xE0` = Read=free (0xE), Write=slot 0 (0x0), `0xEE` = Read=free (0xE), Write=free (0xE)

### Common Pitfalls
- **Variable shadowing with `:=`** - Be careful when reusing error variables in nested scopes
- **Temporary vs permanent file settings** - File settings may need temporary changes (e.g., Write=free) before final restoration
- **Non-fatal operations** - NDEF reads/writes may fail on already-reset tags; handle gracefully

## Project Structure
- `pkg/ntag424/` - Shared NTAG 424 DNA protocol library
- `minter/` - Provisions factory tags with secure keys and SDM
- `reset/` - Restores provisioned tags to factory defaults
- `ro/` - Read-only diagnostic tool (tag state inspection)

## Development Guidelines
- Test both provisioned and factory-default tag states
- Verify both minter and reset compile after shared library changes
- Use `ro` tool to verify tag state before and after operations
