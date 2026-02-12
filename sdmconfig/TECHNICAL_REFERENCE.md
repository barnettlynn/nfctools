# NTAG 424 DNA Technical Reference

This document captures all technical details about communication modes, byte formats, and issues encountered during development.

## Table of Contents

- [Communication Modes](#communication-modes)
- [File Settings Structure](#file-settings-structure)
- [Access Rights Encoding](#access-rights-encoding)
- [SDM Configuration](#sdm-configuration)
- [APDU Command Formats](#apdu-command-formats)
- [Authentication and Secure Messaging](#authentication-and-secure-messaging)
- [Known Issues and Solutions](#known-issues-and-solutions)

---

## Communication Modes

NTAG 424 DNA supports three communication modes for file access:

### Plain Communication (0x00)
- **CLA:** `0x00` (ISO 7816)
- **No encryption, no MAC**
- Commands and responses are sent in clear text
- Used when file access rights = `0xE` (free/no authentication)
- **Example:** `SELECT FILE`, `READ BINARY`, `UPDATE BINARY`

### MAC Communication (0x01)
- **CLA:** `0x90` (proprietary)
- **Commands and responses include MAC for integrity**
- Data is sent in clear text but authenticated
- Requires active authentication session
- **Not fully implemented in this tool**

### Full Communication (0x02)
- **CLA:** `0x90` (proprietary)
- **Data encrypted + MAC for integrity and confidentiality**
- Requires active authentication session
- Used for secure file operations after `AuthenticateEV2First`
- **Example:** `ChangeFileSettings` with secure messaging

### FileOption Byte Format

```
Bit 7   6   5   4   3   2   1   0
    [Reserved]  SDM [Reserved] CommMode
```

- **Bits [1:0]:** Communication mode
  - `00` = Plain
  - `01` = MAC
  - `10` = Full (encryption)
- **Bit 6:** SDM Enable
  - `0` = SDM disabled
  - `1` = SDM enabled
- **Other bits:** Reserved/undefined

**Examples:**
- `0x00` = Plain comm, SDM disabled
- `0x01` = MAC comm, SDM disabled
- `0x40` = Plain comm, SDM enabled
- `0x41` = MAC comm, SDM enabled

---

## File Settings Structure

### Reading File Settings (GetFileSettings)

**Plain Command:**
```
90 F5 00 00 01 <fileNo> 00
```

**Secure Command (after authentication):**
```
90 F5 00 00 <Lc> <fileNo> <MAC(8)> 00
```

**Response Format (SDM disabled):**
```
Offset  Field           Length  Description
------  -----           ------  -----------
0       FileType        1       0x00 = Standard data file
1       FileOption      1       Communication mode + SDM flag
2       AR1             1       RW key | Change settings key
3       AR2             1       Read key | Write key
4-6     FileSize        3       Little-endian
```

**Response Format (SDM enabled):**
```
Offset  Field           Length  Description
------  -----           ------  -----------
0       FileType        1       0x00 = Standard data file
1       FileOption      1       Communication mode + SDM flag (bit 6 = 1)
2       AR1             1       RW key | Change settings key
3       AR2             1       Read key | Write key
4-6     FileSize        3       Little-endian
7       SDMOptions      1       SDM feature flags
8-9     SDMAR           2       SDM access rights (Meta|File|RFU|Ctr)
10+     Offsets         var     UID/Ctr/MAC offsets (conditional)
```

### Changing File Settings (ChangeFileSettings)

**Basic Format (3 bytes - SDM disabled):**
```
FileOption(1) | AR1(1) | AR2(1)
```

**Full Format (SDM enabled):**
```
FileOption(1) | AR1(1) | AR2(1) | SDMOptions(1) | SDMAR(2) | Offsets(var)
```

**SDM Offsets (conditional, based on SDMOptions and SDMAR):**
- **UIDOffset (3 bytes):** Included if `SDMOptions & 0x80` and `SDMMeta == 0x0E`
- **CtrOffset (3 bytes):** Included if `SDMOptions & 0x40` and `SDMMeta == 0x0E`
- **MacInputOffset (3 bytes):** Included if `SDMFile != 0x0F`
- **MacOffset (3 bytes):** Included if `SDMFile != 0x0F`

All offsets are 24-bit little-endian (3 bytes).

---

## Access Rights Encoding

### AR1 (Access Rights 1)
```
Bits:   7 6 5 4   3 2 1 0
        RWKey     ChangeKey
```

**Example: AR1 = 0x20**
- Read+Write key: `0x2` (slot 2)
- Change settings key: `0x0` (slot 0)

### AR2 (Access Rights 2)
```
Bits:   7 6 5 4   3 2 1 0
        ReadKey   WriteKey
```

**Example: AR2 = 0xE2**
- Read key: `0xE` (free/no authentication)
- Write key: `0x2` (slot 2)

### Special Values

- **`0x0` - `0xD`:** Key slot number (0-13)
- **`0xE` (14):** **Free** - No authentication required
- **`0xF` (15):** **Never** - Operation not permitted

**Common Patterns:**

| AR1  | AR2  | Description |
|------|------|-------------|
| 0x00 | 0x00 | Slot 0 for everything |
| 0x20 | 0xE2 | Read=free, Write=slot 2, RW=slot 2, Change=slot 0 |
| 0xE0 | 0xEE | Free R/W, Slot 0 for settings |
| 0xFF | 0xFF | All operations denied |

---

## SDM Configuration

### SDMOptions Byte
```
Bit 7   6   5   4   3   2   1   0
    UID Ctr Rfu Enc TT  Rfu Rfu TT
```

**Bit Meanings:**
- **Bit 7 (0x80):** UID mirroring enabled
- **Bit 6 (0x40):** Read counter mirroring enabled
- **Bit 4 (0x10):** SDM encryption enabled (not used in this tool)
- **Bit 0 (0x01):** Tag tamper status enabled

**Common Value: 0xC1**
- `0x80` - UID mirroring ON
- `0x40` - Counter mirroring ON
- `0x01` - Tag tamper ON
- Total: `0xC1`

### SDMAR (SDM Access Rights) - 2 bytes

Encoded as 16-bit value:
```
Bits:  15-12  11-8   7-4   3-0
       Meta   File   RFU   Ctr
```

**Fields:**
- **Meta (4 bits):** UID/Counter read access
  - `0xE` = Free (no auth needed)
  - `0x0-D` = Key slot
- **File (4 bits):** MAC generation key
  - `0x1` = Slot 1 (typical for SDM key)
  - `0xF` = No MAC (disables MAC offsets)
- **RFU (4 bits):** Reserved (usually `0xF`)
- **Ctr (4 bits):** Counter read key
  - `0x1` = Slot 1 (typical for SDM key)

**Example: SDMAR = 0xE11F**
- Meta: `0xE` (free)
- File: `0x1` (slot 1)
- RFU: `0x1` (should be `0xF`)
- Ctr: `0xF` (never - wrong!)

**Correct Example: SDMAR = 0xE1F1**
- Meta: `0xE` (free)
- File: `0x1` (slot 1 for MAC)
- RFU: `0xF` (reserved)
- Ctr: `0x1` (slot 1 for counter)

### BuildChangeFileSettingsData Logic

```go
// This is the ISSUE we fixed:
fileOption := (commMode & 0x03) | 0x40  // WRONG - always sets SDM bit

// Correct version:
fileOption := (commMode & 0x03)
if sdmOptions != 0x00 {
    fileOption |= 0x40  // Only set SDM bit if enabling
}
```

The original code **always set bit 0x40**, making it impossible to disable SDM!

---

## APDU Command Formats

### ISO 7816 Standard Commands (CLA = 0x00)

#### SELECT FILE
```
00 A4 00 0C 02 <FileID(2)>
```
- **P1:** `0x00` (select by file ID)
- **P2:** `0x0C` (first/only occurrence)
- **Data:** 2-byte file ID (e.g., `0xE104` for NDEF)

#### UPDATE BINARY (Plain)
```
00 D6 <Offset(2)> <Lc> <Data(Lc)>
```
- **Offset:** 2 bytes, big-endian
- **Lc:** Length of data
- **Data:** Bytes to write

**Issues:**
- Plain UPDATE BINARY requires **free write access (0xE)**
- Does NOT work with authenticated sessions
- If file requires authentication, returns **SW=6982** (security not satisfied)

### Proprietary Commands (CLA = 0x90)

#### AuthenticateEV2First
```
// Command 1:
90 71 00 00 02 <KeyNo> 00 00

// Response 1:
<EncRndB(16)> 91 AF

// Command 2:
90 AF 00 00 20 <EncRndA||EncRndB'(32)> 00

// Response 2:
<EncTI||EncRndA'(32)> 91 00
```

#### ChangeFileSettings (Secure Messaging)
```
90 5F 00 00 <Lc> <FileNo> <EncData> <MAC(8)> 00
```

**Secure Messaging Wrapper:**
- **Header:** `FileNo` (1 byte, unencrypted)
- **EncData:** Encrypted and padded file settings
- **MAC:** 8-byte truncated CMAC

---

## Authentication and Secure Messaging

### EV2 Authentication Flow

1. **Card sends encrypted RndB (16 bytes)**
2. **PCD generates RndA (16 bytes)**
3. **PCD sends encrypted RndA || rotate_left(RndB)**
4. **Card responds with encrypted TI || rotate_left(RndA)**
5. **Session keys derived from RndA, RndB, and TI**

### Session Key Derivation

```
SV1 = A5 5A 00 01 00 80 | RndA[0:2] | (RndA[2:8] XOR RndB[0:6]) | RndB[6:16] | RndA[8:16]
SV2 = 5A A5 00 01 00 80 | RndA[0:2] | (RndA[2:8] XOR RndB[0:6]) | RndB[6:16] | RndA[8:16]

KENC = CMAC(Key, SV1)  // Encryption key
KMAC = CMAC(Key, SV2)  // MAC key
```

### Secure Messaging Format

**Command:**
```
CmdCtr(2) | TI(4) | Header | EncData | MAC(8)
```

**MAC Input:**
```
Cmd(1) | CmdCtr(2) | TI(4) | Header | EncData
```

**Response:**
```
EncData | MAC(8)
```

**MAC Input (Response):**
```
SW2(1) | CmdCtr+1(2) | TI(4) | EncData
```

### Critical Rules

1. **SelectNDEFApp or SelectFile INVALIDATES authentication**
   - Must re-authenticate after selecting
   - Or select BEFORE authenticating

2. **Plain commands don't carry authentication**
   - Even after successful auth, plain UPDATE BINARY needs free access
   - Use secure messaging OR free access rights

3. **ChangeFileSettings uses secure messaging**
   - Always requires authentication
   - Command counter increments with each secure command

---

## Known Issues and Solutions

### Issue 1: GetFileSettings Returns SW=917E

**Symptom:**
```
GetFileSettings error: plain SW=917E; secure err: cmd 0xF5 failed (SW=917E)
```

**SW=917E:** Wrong length / Le incorrect

**Possible Causes:**
1. When SDM is enabled, file settings response is longer
2. Secure messaging format might be incorrect
3. Command counter might be out of sync
4. Session might be stale after ChangeFileSettings

**Current Workaround:**
- Fall back to hard-coded AR1=0x20, AR2=0x22
- Still investigating root cause

**Investigation Needed:**
- Add debug output for APDU exchange
- Check if Le field is correct
- Verify session state
- Try reading File 1 (CC) settings for comparison

### Issue 2: WriteNDEFWithAuth Fails with SW=6982

**Symptom:**
```
Write NDEF failed: UPDATE BINARY failed (SW=6982)
```

**SW=6982:** Security status not satisfied

**Root Cause:**
`WriteNDEFWithAuth` calls `SelectFile` before writing:

```go
func WriteNDEFWithAuth(card Card, data []byte) error {
    if err := SelectFile(card, ndefFileID); err != nil {
        return err
    }
    return WriteNDEFData(card, data)  // Plain UPDATE BINARY
}
```

**Problem:**
1. SelectFile uses plain SELECT (0x00 0xA4)
2. Plain SELECT invalidates authentication session
3. WriteNDEFData uses plain UPDATE BINARY (0x00 0xD6)
4. File requires authentication (AR2 != 0xE)
5. No active session → SW=6982

**Solution:**
```go
// Select file BEFORE authentication
ntag.SelectFile(card, 0xE104)
ntag.AuthenticateEV2First(card, key, keyNo)
ntag.WriteNDEFData(card, data)  // Now authenticated
```

**Better Solution (used in workflows):**
1. Set AR2=0xEE (free write) before writing
2. Use plain writes without authentication
3. Restore original AR2 after writing

### Issue 3: Cannot Disable SDM

**Symptom:**
ChangeFileSettings always enables SDM even when trying to disable it.

**Root Cause:**
```go
fileOption := (commMode & 0x03) | 0x40  // Always sets bit 6!
```

**Fix:**
```go
fileOption := (commMode & 0x03)
if sdmOptions != 0x00 {
    fileOption |= 0x40  // Only set if enabling
}
```

### Issue 4: ChangeFileSettings Length Error (SW=917E)

**Symptom:**
When trying to disable SDM with full ChangeFileSettingsSDM format:
```
ChangeFileSettings failed: cmd 0x5F failed (SW=917E)
```

**Root Cause:**
When `SDMOptions=0x00` and `SDMFile=0x0F`, the BuildChangeFileSettingsData function omits MAC offsets (lines 77-80). But the card might expect a specific format.

**Solution:**
Use `ChangeFileSettingsBasic` (3 bytes only) to disable SDM:
```go
// Disable SDM: send only 3 bytes
data := []byte{fileOption, ar1, ar2}
```

---

## NDEF File Structure

### File IDs
- **0xE103:** Capability Container (CC) file
- **0xE104:** NDEF file (File 2)
- **0xE105:** Proprietary file (File 3)

### Typical File 2 Configuration

**Without SDM:**
```
FileType:    0x00 (standard data)
FileOption:  0x00 (plain, SDM disabled)
AR1:         0x20 (RW=2, Change=0)
AR2:         0xE2 (Read=free, Write=2)
Size:        256 bytes
```

**With SDM Enabled:**
```
FileType:    0x00
FileOption:  0x40 (plain, SDM enabled)
AR1:         0x20 (RW=2, Change=0)
AR2:         0xE2 (Read=free, Write=2)
SDMOptions:  0xC1 (UID | Ctr | TT)
SDMMeta:     0x0E (free)
SDMFile:     0x01 (slot 1 for MAC)
SDMCtr:      0x01 (slot 1 for counter)
UIDOffset:   36 (0x24)
CtrOffset:   55 (0x37)
MacInputOffset: 32 (0x20)
MacOffset:   66 (0x42)
```

### SDM URL Template Format

```
https://api.guideapparel.com/tap?uid=00000000000000&ctr=000000&mac=0000000000000000
                                    ^              ^      ^
                                    |              |      |
                                 UIDOffset    CtrOffset MacOffset
```

**MacInputOffset** points to where MAC calculation starts (usually start of UID parameter).

---

## Workflow Implementation Details

### Disable SDM Workflow

```go
// Set FileOption=0x00 (SDM disabled, plain comm)
// Set AR2=0xEE (free write for future operations)
fs := &FileSettings{
    FileOption: 0x00,
    AR1:        currentAR1,  // Preserve (usually 0x20)
    AR2:        0xEE,        // Free write
}
ChangeFileSettingsBasic(card, session, fileNo, fs.FileOption, fs.AR1, fs.AR2)
```

**Why AR2=0xEE?**
- Allows subsequent plain NDEF writes without authentication
- `0xE` = free for write
- `0xE` = free for RW
- Change settings (AR1) still protected by slot 0

### Enable SDM Workflow

```go
// Step 1: Write NDEF (assumes AR2=0xEE from disable)
WriteNDEFPlain(card, ndefData)

// Step 2: Enable SDM and restore access rights
fs := &FileSettings{
    FileOption: 0x40,    // SDM enabled
    AR1:        0x20,    // Restore (RW=slot 2, Change=slot 0)
    AR2:        0xE2,    // Restore (Read=free, Write=slot 2)
    SDMOptions: 0xC1,
    SDMMeta:    0x0E,
    SDMFile:    sdmKeyNo,
    SDMCtr:     sdmKeyNo,
}
ChangeFileSettingsSDM(card, session, fileNo, commMode,
    fs.AR1, fs.AR2, fs.SDMOptions, fs.SDMMeta,
    fs.SDMFile, fs.SDMCtr, uidOffset, ctrOffset,
    macInputOffset, macOffset)
```

### Update SDM Workflow

Combines disable → write → enable in sequence.

---

## Debug Tips

### Enable APDU Debug Output

```bash
go run . --update-sdm --debug-apdu
```

**Output Format:**
```
APDU cmd 0x5F: 905F00000E02...
ENC: F485A822...
MAC input: 5F0000...
MACT: 47AE8A29...
```

### Diagnose Authentication

```bash
go run . --diag-auth
```

Tests slots 0-15 with the settings key to find which slots authenticate successfully.

### Common Error Codes

| SW    | Meaning | Common Cause |
|-------|---------|--------------|
| 9000  | Success | - |
| 9100  | Success (more data) | - |
| 6982  | Security not satisfied | No auth or wrong key |
| 917E  | Wrong length | APDU format issue |
| 91AE  | Authentication error | Wrong key for slot |
| 9140  | No changes | Settings same as current |
| 919E  | Invalid parameter | Bad file settings data |

---

## Best Practices

1. **Always verify key slot configuration before operations**
   - Use `--diag-auth` to test authentication
   - Confirm which slots are provisioned

2. **Select files before authentication**
   - Prevents session invalidation
   - Or re-select NDEF app between operations

3. **Use appropriate communication mode**
   - Plain (0x00) for unauthenticated operations
   - Secure messaging for ChangeFileSettings
   - Match FileOption with actual operation type

4. **Preserve access rights when possible**
   - Read current settings before modifying
   - Only change what's necessary
   - Restore original rights after temp changes

5. **Handle errors gracefully**
   - SW=917E on GetFileSettings → use fallback AR
   - SW=6982 on write → check authentication and AR
   - SW=91AE on auth → verify key file and slot number

6. **Test with a single tag first**
   - Verify workflows before batch operations
   - Keep backups of original file settings
   - Document any non-standard configurations

---

## References

- **NTAG 424 DNA Datasheet:** NXP Product data sheet (NT4H2421Gx)
- **ISO/IEC 7816-4:** Identification cards - Integrated circuit cards
- **Application Note AN12196:** NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints

---

## Glossary

- **AR:** Access Rights
- **APDU:** Application Protocol Data Unit
- **CAR:** Change Access Rights
- **CC:** Capability Container
- **CLA:** Class byte in APDU
- **CMAC:** Cipher-based MAC (AES-CMAC)
- **Lc:** Length of command data
- **Le:** Length of expected response
- **MAC:** Message Authentication Code
- **NDEF:** NFC Data Exchange Format
- **PCD:** Proximity Coupling Device (reader)
- **PICC:** Proximity Integrated Circuit Card (tag)
- **SDM:** Secure Dynamic Messaging
- **SW:** Status Word (2 bytes: SW1 SW2)
- **TI:** Transaction Identifier
- **UID:** Unique Identifier

