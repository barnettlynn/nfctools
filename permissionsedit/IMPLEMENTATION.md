# NTAG 424 DNA File Permissions Editor - Implementation Details

## Overview

The `permissionsedit` tool reads and modifies file access permissions on NTAG 424 DNA tags. It handles both **encrypted** and **plain** communication modes, which was critical for supporting all three file types.

## File Structure on NTAG 424 DNA

The NDEF application (AID: `D2 76 00 00 85 01 01`) contains three files:

- **File 1**: Capability Container (CC) - Describes tag capabilities (32 bytes)
- **File 2**: NDEF Data File - Stores NFC Data Exchange Format records
- **File 3**: Proprietary Data File - Application-specific data

## Communication Modes

Each file has a `CommMode` setting that determines how data is transmitted:

| CommMode | Value | Description |
|----------|-------|-------------|
| **Plain** | 0x00 | No encryption, data sent in cleartext |
| **MAC** | 0x01 | Data in cleartext but authenticated with CMAC |
| **Full** | 0x03 | Data encrypted with AES-128 and authenticated with CMAC |

## The File 1 Challenge

### Initial Configuration

On this specific NTAG 424 DNA tag:

| File | Name | CommMode | Why This Matters |
|------|------|----------|-----------------|
| File 1 | CC | **Plain** (0x00) | Returns plain data even in secure session |
| File 2 | NDEF | **Plain** (0x00) | Returns plain data even in secure session |
| File 3 | Proprietary | **Full** (0x03) | Returns encrypted data in secure session |

### Key Discovery

**Even when authenticated with EV2 secure messaging, files with CommMode=Plain return their data in PLAIN format, not encrypted!**

This is by design - the `CommMode` setting controls the file's response format regardless of the session authentication state.

### Why This Broke Initially

The original code assumed all responses in a secure session would be:
```
[Status: 0x00] + [Encrypted data (16-byte aligned)] + [CMAC (8 bytes)]
```

But Files 1 and 2 actually returned:
```
[Plain data (7 bytes)] + [CMAC (8 bytes)]
```

### Response Format Comparison

#### Encrypted Response (File 3 - CommMode=Full)

When using authenticated GetFileSettings (0xF5):

```
Raw response from card:
  [Status: 0x00] + [Encrypted data: 16 bytes] + [CMAC: 8 bytes] + [SW1SW2: 0x91 0x00]

After transmit() strips SW1SW2:
  [0x00] + [16 encrypted bytes] + [8 MAC bytes] = 25 bytes

Processing:
  1. Skip status byte (0x00)
  2. Remaining: 24 bytes
  3. Last 8 bytes = MAC
  4. First 16 bytes = encrypted data
  5. Decrypt with AES-CBC using session key
  6. Unpad with ISO9797-M2
  7. Verify MAC
  8. Return decrypted data (7 bytes of file settings)
```

#### Plain Response (Files 1 & 2 - CommMode=Plain)

When using authenticated GetFileSettings (0xF5):

```
Raw response from card:
  [Plain data: 7 bytes] + [CMAC: 8 bytes] + [SW1SW2: 0x91 0x00]

After transmit() strips SW1SW2:
  [7 plain bytes] + [8 MAC bytes] = 15 bytes

Processing:
  1. Do NOT skip any bytes - first 0x00 is file type!
  2. Last 8 bytes = MAC
  3. First 7 bytes = plain data
  4. Verify MAC (calculated over plain data)
  5. Return plain data directly (7 bytes of file settings)
```

**Critical difference**: Plain responses have **NO status byte** to skip. The first `0x00` is the **file type** (Standard Data File), not a status byte!

### Example: File 1 Response Breakdown

**Actual bytes received** (after SW1SW2 stripped): 15 bytes
```
00 00 00 E0 20 00 00 | 2D 4A 1A C8 34 91 D1 D2
└─── Plain Data ────┘   └────── CMAC ──────────┘
     (7 bytes)                  (8 bytes)
```

**Parsing the plain data** (7 bytes):
```
Byte 0: 0x00 → File Type = 0x00 (Standard Data File)
Byte 1: 0x00 → File Option = 0x00 (CommMode=Plain, no SDM)
Byte 2: 0x00 → AR1 (Access Rights 1)
Byte 3: 0xE0 → AR2 (Access Rights 2)
Byte 4-6: 0x20 0x00 0x00 → File Size = 32 bytes (little-endian)
```

**Access Rights Decoding**:

`AR1 = 0x00`:
- `ReadWrite key = (0x00 >> 4) & 0x0F = 0x0` → Key 0 (AppMaster)
- `ChangeAccess key = 0x00 & 0x0F = 0x0` → Key 0 (AppMaster)

`AR2 = 0xE0`:
- `Read key = (0xE0 >> 4) & 0x0F = 0xE` → **0xE = Free** (no authentication required)
- `Write key = 0xE0 & 0x0F = 0x0` → Key 0 (AppMaster)

**Result**:
```
File 1 (CC):
  CommMode:     Plain
  Read:         Free           (0xE)
  Write:        Key 0 (AppMaster)
  ReadWrite:    Key 0 (AppMaster)
  ChangeAccess: Key 0 (AppMaster)
```

This matches the displayed output perfectly!

## The Solution

### Detecting Encrypted vs Plain Responses

The code now distinguishes between encrypted and plain responses **before** processing:

```go
// Calculate potential encrypted data length
respEncLen := len(resp) - 8  // Assume last 8 bytes are MAC

// Check if block-aligned (encrypted) or not (plain)
isEncrypted := (respEncLen == 0 || respEncLen%16 == 0)
```

**Why this works**:
- **Encrypted data**: Always padded to 16-byte blocks (AES requirement)
  - Examples: 0, 16, 32, 48 bytes
- **Plain data**: No padding requirement
  - File settings = 7 bytes (not a multiple of 16)

### Processing Logic

```go
if isEncrypted {
    // Skip status byte for encrypted responses
    if resp[0] == 0x00 {
        resp = resp[1:]
    }

    // Extract encrypted data and MAC
    respEnc = resp[:respEncLen]
    respMac = resp[respEncLen:]

    // Decrypt
    plaintext = AES_CBC_Decrypt(respEnc, sessionKey, IV)
    plaintext = RemovePadding(plaintext)

} else {
    // Plain response - do NOT skip any bytes!
    // First 0x00 is file type, not status byte

    respPlain = resp[:respEncLen]
    respMac = resp[respEncLen:]

    // Use plain data directly (no decryption needed)
    plaintext = respPlain
}

// Verify MAC (same for both encrypted and plain)
VerifyMAC(plaintext, respMac, sessionKey)

return plaintext
```

### MAC Calculation

For both encrypted and plain responses, the MAC is calculated the same way:

```
CMAC_Input = SW2 (0x00) || CmdCtr+1 (2 bytes) || TI (4 bytes) || ResponseData

Where ResponseData is:
  - Encrypted bytes (for encrypted responses)
  - Plain bytes (for plain responses)
```

The CMAC is then truncated to 8 bytes by taking odd-indexed bytes:
```
CMAC[1], CMAC[3], CMAC[5], CMAC[7], CMAC[9], CMAC[11], CMAC[13], CMAC[15]
```

## Why File 1 Requires Authentication to Read Settings

Even though File 1 has `CommMode=Plain` and `Read=Free`, reading **file settings** (via GetFileSettings 0xF5 command) still requires authentication.

This is because:
1. **Reading file DATA** (via ReadData command) respects the Read access rights
2. **Reading file METADATA** (settings) always requires authentication
3. The plain-mode GetFileSettings command (SW=917E) failed
4. Only the authenticated secure-session GetFileSettings succeeded

The settings themselves are returned in plain format because the file's `CommMode=Plain`, but the command still needs to be executed in an authenticated session.

## Summary

| Aspect | File 1 & 2 (CommMode=Plain) | File 3 (CommMode=Full) |
|--------|----------------------------|------------------------|
| Response format | Plain data + MAC | Status + Encrypted data + MAC |
| Status byte | None (0x00 is file type!) | Present (must skip) |
| Data length | 7 bytes (not aligned) | 16 bytes (block-aligned) |
| Processing | Verify MAC, use plain data | Skip status, decrypt, verify MAC |
| Authentication | Required for GetFileSettings | Required for GetFileSettings |

The key insight was recognizing that `CommMode` affects the response format even within an authenticated session, and plain responses don't have a status byte to skip - the first `0x00` is meaningful data (the file type).
