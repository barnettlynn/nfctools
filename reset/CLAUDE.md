# Reset Tool - Implementation Notes

## Purpose
Restores provisioned NTAG 424 DNA tags to factory defaults by reversing all changes made by the minter tool.

## Reset Sequence (14 Steps)

### Phase 1: Capture State (Steps 1-3)
1. Get UID for identification
2. Read current NDEF (non-fatal, for logging)
3. Read file 2 settings (non-fatal, for before/after comparison)

### Phase 2: Authentication & NDEF Clear (Steps 4-7)
4. Select NDEF application
5. Authenticate with app master key (slot 0) - tries custom key, falls back to zeros
6. **Temporarily** set file 2 to Write=free (AR2=0xEE) - allows unauthenticated NDEF clear
7. Clear NDEF data using ISO write (non-fatal)

### Phase 3: Key Reset (Steps 8-12)
8. Reset key slot 1 to zeros (SDM key)
9. Reset key slot 2 to zeros (NDEF write key)
10. Reset key slot 3 to zeros (unused, but must be explicit)
11. Reset key slot 4 to zeros (unused, but must be explicit)
12. Reset key slot 0 to zeros (app master key) - **invalidates session**

**Important**: Slots 3-4 must be explicitly reset even though they were never changed from zeros.

### Phase 4: File Settings Restoration (Step 13)
13. Re-authenticate with zero key, then restore all three files to factory defaults:
    - File 1 (CC): FileOption=0x00, AR1=0x00, AR2=0xE0
    - File 2 (NDEF): FileOption=0x00, AR1=0x00, AR2=0xE0 *(corrects temporary 0xEE)*
    - File 3 (Proprietary): FileOption=0x03, AR1=0x00, AR2=0x00

### Phase 5: Verification (Step 14)
14. Verify file settings (non-fatal)

## Key Implementation Details

### tryChangeKey Helper
Attempts key change with primary old key, falls back to alternative if different:
- For provisioned tags: tries custom key first, falls back to zeros
- For factory tags: tries zeros first, falls back to custom key
- Re-authenticates between attempts to get fresh session

### Session Invalidation
Changing the authenticated key slot (slot 0) invalidates the session:
- Must re-select application
- Must re-authenticate with new zero key
- Only then can file settings be restored

### File Settings Strategy
Two-phase approach required:
1. **Temporary settings** (Step 6): Set Write=free to allow NDEF clear without auth
2. **Final restoration** (Step 13): Restore all files to true factory defaults after keys are reset

Cannot restore file settings to final state before NDEF clear because factory AR2=0xE0 requires authentication for writes.

## Testing
After running reset, verify with `ro` tool:
- All 5 key slots = 16 zero bytes
- File 1: FileOption=0x00, AR2=0xE0
- File 2: FileOption=0x00, AR2=0xE0, SDM disabled, NDEF empty
- File 3: FileOption=0x03, AR2=0x00

## Common Issues
- **Session invalidation**: Forgetting to re-auth after slot 0 change
- **Incomplete file restoration**: Only setting file 2, missing files 1 and 3
- **Partial key reset**: Missing slots 3-4
- **Variable shadowing**: Using `:=` in nested scopes shadows outer `err` variable
