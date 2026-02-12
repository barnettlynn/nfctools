# NTAG 424 DNA Communication Walkthrough

This document walks through the complete APDU-level communication flow for common operations, showing exactly what bytes are sent and received.

## Table of Contents
1. [Background: APDU Structure](#background-apdu-structure)
2. [GetFileSettings - Plain Command](#getfilesettings---plain-command)
3. [GetFileSettings - Secure Command](#getfilesettings---secure-command)
4. [ChangeFileSettings - Secure Command](#changefilesettings---secure-command)
5. [Reading NDEF Data from File 2](#reading-ndef-data-from-file-2)
6. [Writing NDEF Data to File 2](#writing-ndef-data-to-file-2)

---

## Background: APDU Structure

### ISO 7816-4 APDU Format

**Command APDU:**
```
[CLA] [INS] [P1] [P2] [Lc] [Data...] [Le]
```

- **CLA** (1 byte): Class byte
  - `0x90` = DESFire native commands
  - `0x00` = ISO 7816 commands
- **INS** (1 byte): Instruction code
- **P1, P2** (2 bytes): Parameters
- **Lc** (1 byte): Length of command data (optional)
- **Data** (Lc bytes): Command data (optional)
- **Le** (1 byte): Expected response length (optional)
  - `0x00` = up to 256 bytes
  - Other value = exact number of bytes expected

**Response APDU:**
```
[Data...] [SW1] [SW2]
```

- **Data** (variable): Response data
- **SW1 SW2** (2 bytes): Status word
  - `0x9000` = Success
  - `0x9100` = Success (DESFire AF/additional frame)
  - `0x917E` = DESFire length error
  - `0x91AE` = DESFire authentication error
  - `0x6982` = Security status not satisfied

---

## GetFileSettings - Plain Command

### Context
- Operation: Read File 2 settings without authentication
- File 2 has AR1=0xE0 (free read, slot 0 for change settings)
- File 2 has AR2=0xEE (free write)
- SDM is currently disabled

### Command Construction

We want to read settings for File 2 (file number = 0x02).

**Attempt 1: Le=0x20**
```
Raw APDU: 90 F5 00 00 01 02 20
```

Breaking down:
- `90` = CLA (DESFire native command)
- `F5` = INS (GetFileSettings)
- `00` = P1 (not used)
- `00` = P2 (not used)
- `01` = Lc (1 byte of data follows)
- `02` = Data (file number 2)
- `20` = Le (expecting 32 bytes response)

**Response:**
```
SW1 SW2: 91 7E
Data: (none)
```

Status word = 0x917E = LENGTH_ERROR
The tag doesn't like Le=0x20 (expecting 32 bytes).

**Attempt 2: Le=0x10**
```
Raw APDU: 90 F5 00 00 01 02 10
```
Same as above, but Le=0x10 (expecting 16 bytes).

**Response:** `91 7E` (LENGTH_ERROR)

**Attempt 3: No Le**
```
Raw APDU: 90 F5 00 00 01 02
```
No Le field at all.

**Response:** `91 7E` (LENGTH_ERROR)

**Attempt 4: Le=0x00** ✅ SUCCESS
```
Raw APDU: 90 F5 00 00 01 02 00
```

Breaking down:
- Same as attempt 1, but:
- `00` = Le (expecting up to 256 bytes, let tag return whatever it has)

**Response:**
```
Data: 00 00 E0 EE 00 00 00
SW1 SW2: 91 00
```

Status word = 0x9100 = SUCCESS!

### Response Parsing

The response data is 7 bytes when SDM is disabled:
```
Byte 0: 00    = File type (0x00 = standard data file)
Byte 1: 00    = FileOption (bits 7:0)
                  bit 6 = 0 → SDM disabled
                  bits 1:0 = 00 → Plain communication
Byte 2: E0    = AR1 (Access Rights 1)
Byte 3: EE    = AR2 (Access Rights 2)
Byte 4: 00    = File size byte 0 (LSB)
Byte 5: 00    = File size byte 1
Byte 6: 00    = File size byte 2 (MSB)
```

**Parsing AR1 (0xE0):**
```
AR1 = 0xE0 = binary 1110 0000
  Upper nibble (bits 7:4) = 0xE (14) = ReadWrite key
  Lower nibble (bits 3:0) = 0x0      = ChangeSettings key

So:
  ReadWrite: Key 0xE (14) = free (no authentication needed)
  ChangeSettings: Key 0 (slot 0)
```

**Parsing AR2 (0xEE):**
```
AR2 = 0xEE = binary 1110 1110
  Upper nibble (bits 7:4) = 0xE = Read key
  Lower nibble (bits 3:0) = 0xE = Write key

So:
  Read: Key 0xE = free
  Write: Key 0xE = free
```

### Why Le=0x00 Works

The NTAG 424 DNA GetFileSettings returns:
- **7 bytes** when SDM is disabled
- **10+ bytes** when SDM is enabled (includes SDM configuration)

When we specify:
- Le=0x20 (32 bytes) → Tag rejects because response is only 7 bytes
- Le=0x10 (16 bytes) → Tag rejects because response is only 7 bytes
- Le=none → Tag rejects (Le is required for this command)
- **Le=0x00 → Tag accepts** (means "return whatever you have, up to 256 bytes")

---

## GetFileSettings - Secure Command

### Context
- When AR1 doesn't allow free read (e.g., AR1=0x20 means Read requires key slot 2)
- We need to authenticate first, then use secure messaging

### Step 1: Authentication (EV2First)

This is a multi-step process that establishes session keys. I'll show the final state after authentication:

**Session State After Auth:**
```
Session keys (derived from app master key):
  kenc[16] = encryption key (used for AES-128 CBC)
  kmac[16] = MAC key (used for AES CMAC)
  ti[4]    = transaction identifier
  cmdCtr   = command counter (starts at 0)
```

### Step 2: Build Secure GetFileSettings Command

We want to read File 2 settings using secure messaging.

**Input Parameters:**
- cmd = 0xF5 (GetFileSettings)
- header = [0x02] (file number)
- data = [] (no additional data)

**Building the APDU:**

1. **Encrypt the data** (if any)
   - In this case, data is empty, so encData = []

2. **Build MAC input:**
   ```
   MAC input format:
   [cmd] [cmdCtr_LSB] [cmdCtr_MSB] [ti[4]] [header] [encData]
   ```

   Example (cmdCtr=0x028F):
   ```
   F5             = cmd
   8F 02          = cmdCtr (little-endian)
   FF 98 02 00    = ti (4 bytes - example values)
   02             = header (file number)
                  = (no encData)

   Full MAC input: F5 8F 02 FF 98 02 00 02
   ```

3. **Calculate MAC:**
   ```
   CMAC = AES_CMAC(kmac, MAC_input)
        = (16 bytes)

   MACT = truncate odd bytes from CMAC
        = take bytes 1, 3, 5, 7, 9, 11, 13, 15 (8 bytes)
        = 30 B1 F7 3F 9F F9 5E B2 (example)
   ```

4. **Build final APDU:**
   ```
   Format: 90 [cmd] 00 00 [Lc] [header] [encData] [MACT] 00

   Lc = len(header) + len(encData) + len(MACT)
      = 1 + 0 + 8 = 9

   Final APDU: 90 F5 00 00 09 02 30 B1 F7 3F 9F F9 5E B2 00
   ```

**Send to card:**
```
Command: 90 F5 00 00 09 02 30 B1 F7 3F 9F F9 5E B2 00
```

**Response from card:**
```
Data: [encrypted_data] [response_MAC]
SW: 91 7E  ← LENGTH_ERROR!
```

Why does this fail? Same Le=0x00 issue as with plain commands, but the secure messaging wrapper adds complexity.

**Note:** This is why we try plain commands first with different Le values before falling back to secure messaging.

---

## ChangeFileSettings - Secure Command

This operation ALWAYS requires secure messaging (can't be done plain).

### Context
- We want to disable SDM on File 2
- Current state: SDM may be enabled or disabled
- New state: SDM disabled, AR1=0xE0, AR2=0xEE

### Step 1: Prepare Data

**For basic ChangeFileSettings (disabling SDM):**
```
Data format: [FileOption] [AR1] [AR2]

FileOption = 0x00  (bit 6=0 → SDM disabled, bits 1:0=00 → plain comm)
AR1 = 0xE0         (free read, slot 0 for change settings)
AR2 = 0xEE         (free write)

Data = [00 E0 EE]
```

### Step 2: Build Secure APDU

Let's walk through building the secure messaging APDU:

**Session state (example):**
```
kenc = (16-byte encryption key from auth)
kmac = (16-byte MAC key from auth)
ti = [E8 2E 21 17]
cmdCtr = 0x00E8 (after previous commands)
```

#### 2.1: Calculate Encryption IV

```
IVC input (16 bytes):
  Byte 0:    A5           (constant)
  Byte 1:    5A           (constant)
  Bytes 2-5: E8 2E 21 17  (ti)
  Byte 6:    E8           (cmdCtr LSB)
  Byte 7:    00           (cmdCtr MSB)
  Bytes 8-15: 00...00     (padding)

IVC input = A5 5A E8 2E 21 17 E8 00 00 00 00 00 00 00 00 00

IVC = AES_ECB_encrypt(kenc, IVC_input)
    = (16-byte IV for CBC)
```

#### 2.2: Encrypt the Data

```
Data = 00 E0 EE  (3 bytes)

Padded data (ISO 9797 Method 2):
  Add 0x80, then pad with 0x00 to reach 16-byte boundary
  = 00 E0 EE 80 00 00 00 00 00 00 00 00 00 00 00 00

Encrypted = AES_CBC_encrypt(kenc, IVC, padded_data)
          = 31 1E 9A 59 9E 25 30 0A 39 A9 A2 EF 08 BB 2C BD
            (16 bytes)
```

#### 2.3: Build MAC Input

```
MAC input format:
[cmd] [cmdCtr_LSB] [cmdCtr_MSB] [ti] [header] [encrypted_data]

cmd = 5F
cmdCtr = 00E8
ti = E8 2E 21 17
header = 02 (file number)
encrypted = 31 1E 9A 59 9E 25 30 0A 39 A9 A2 EF 08 BB 2C BD

MAC input = 5F E8 00 E8 2E 21 17 02 31 1E 9A 59 9E 25 30 0A 39 A9 A2 EF 08 BB 2C BD
          (25 bytes)
```

#### 2.4: Calculate MAC

```
CMAC = AES_CMAC(kmac, MAC_input)
     = (16 bytes full CMAC)

MACT = truncate odd bytes
     = 6C E9 39 D2 92 8A D7 18
       (8 bytes)
```

#### 2.5: Construct Final APDU

```
Format: 90 [cmd] 00 00 [Lc] [header] [encrypted] [MACT] 00

Lc = 1 + 16 + 8 = 25 = 0x19

APDU = 90 5F 00 00 19 02 31 1E 9A 59 9E 25 30 0A 39 A9 A2 EF 08 BB 2C BD 6C E9 39 D2 92 8A D7 18 00
```

**Send to card:**
```
90 5F 00 00 19 02 31 1E 9A 59 9E 25 30 0A 39 A9 A2 EF 08 BB 2C BD 6C E9 39 D2 92 8A D7 18 00
```

### Step 3: Receive and Validate Response

**Response from card:**
```
Data: 00 00 00 00 00 00 00 00
SW: 91 00
```

The response is 8 bytes: all zeros (encrypted status) + MAC.

Actually, if the command has no return data, the response is just the 8-byte MAC:
```
Response MAC = 00 00 00 00 00 00 00 00 (example - actual will vary)
SW = 91 00 (SUCCESS)
```

#### 3.1: Validate Response MAC

```
cmdCtr1 = cmdCtr + 1 = 0x00E9

IVR input (16 bytes):
  Byte 0:    5A           (constant - note: reversed from IVC)
  Byte 1:    A5           (constant - note: reversed from IVC)
  Bytes 2-5: E8 2E 21 17  (ti)
  Byte 6:    E9           (cmdCtr1 LSB)
  Byte 7:    00           (cmdCtr1 MSB)
  Bytes 8-15: 00...00     (padding)

IVR = AES_ECB_encrypt(kenc, IVR_input)

Response MAC input:
[SW_LSB] [cmdCtr1_LSB] [cmdCtr1_MSB] [ti] [encrypted_response_data]

SW = 0x9100, so SW_LSB = 0x00
cmdCtr1 = 0x00E9
ti = E8 2E 21 17
encrypted_response_data = (none for this command)

MAC input = 00 E9 00 E8 2E 21 17
          (7 bytes)

Expected CMAC = AES_CMAC(kmac, MAC_input)
Expected MACT = truncate odd bytes

Compare Expected MACT with received response MAC
If they match → command succeeded
If they don't match → MAC verification failed!
```

#### 3.2: Update Session State

```
sess.cmdCtr = cmdCtr1 = 0x00E9

This is important! The command counter increments with each secure command.
Next command will use cmdCtr = 0x00E9.
```

---

## Reading NDEF Data from File 2

### Context
- File 2 is the NDEF file (Standard Data File)
- File ID = 0xE104 (in NDEF application context)
- We want to read the NDEF message

### Step 1: Select NDEF Application

**Command:**
```
AID = D2 76 00 00 85 01 01 (NDEF application)

APDU: 00 A4 04 00 07 D2 76 00 00 85 01 01 00

Breaking down:
  00 = CLA (ISO 7816)
  A4 = INS (SELECT)
  04 = P1 (select by DF name/AID)
  00 = P2
  07 = Lc (7 bytes of data)
  D2 76 00 00 85 01 01 = AID
  00 = Le
```

**Response:**
```
SW: 91 00 (SUCCESS)
```

### Step 2: Select File 2 (NDEF File)

**Command:**
```
File ID = E104

APDU: 00 A4 00 0C 02 E1 04

Breaking down:
  00 = CLA
  A4 = INS (SELECT)
  00 = P1 (select by file ID)
  0C = P2 (no FCI response)
  02 = Lc (2 bytes)
  E1 04 = file ID
  (no Le)
```

**Response:**
```
SW: 91 00 (SUCCESS)
```

### Step 3: Read NDEF Data (Plain - if AR allows)

**READ BINARY command (ISO 7816-4):**

Assuming we want to read 255 bytes starting at offset 0:

```
APDU: 00 B0 00 00 FF

Breaking down:
  00 = CLA
  B0 = INS (READ BINARY)
  00 00 = P1 P2 (offset = 0x0000)
  FF = Le (read 255 bytes)
```

**Response (example):**
```
Data: 00 1B D1 01 17 55 04 61 70 69 2E 67 75 69 64 65 ...
      (NDEF message data - up to 255 bytes)
SW: 90 00 (SUCCESS)
```

#### Parsing NDEF Response

```
Byte 0: 00    = NDEF length MSB
Byte 1: 1B    = NDEF length LSB (27 bytes)
Bytes 2-28: D1 01 17 55 04 ... = NDEF message (27 bytes)
```

**NDEF Message Structure (from byte 2):**
```
Byte 0: D1    = NDEF header
              bit 7 = 1 (MB - message begin)
              bit 6 = 1 (ME - message end)
              bit 5 = 0 (CF - not chunked)
              bit 4 = 1 (SR - short record)
              bit 3-0 = 0001 (TNF - well-known type)

Byte 1: 01    = Type length (1 byte)
Byte 2: 17    = Payload length (23 bytes)
Byte 3: 55    = Type = 'U' (URI record)
Byte 4: 04    = URI identifier code
              0x04 = "https://"
Bytes 5-27:   = URI (without https:// prefix)
              61 70 69 2E 67... = "api.guide..."
```

### Step 4: Read NDEF Data (Authenticated - if AR requires)

If File 2 has AR1=0x20 (read requires key slot 2):

1. Authenticate with key slot 2 (EV2First)
2. Build secure READ BINARY (not shown - similar to ChangeFileSettings)
3. Decrypt response data
4. Parse NDEF

**Note:** Standard ISO READ BINARY doesn't support secure messaging well with DESFire. Better to use plain reads with free access (AR1=0xE0).

---

## Writing NDEF Data to File 2

### Context
- File 2 must have free write access (AR2=0xEE)
- SDM must be disabled (when SDM is enabled, File 2 becomes read-only)
- We want to write a new NDEF message

### Step 1: Prepare NDEF Data

**Example NDEF URL:**
```
URL: https://api.guideapparel.com/tap?uid=00000000000000&ctr=000000&mac=0000000000000000
```

**Build NDEF message:**
```
NDEF Record:
  Header: D1 (MB=1, ME=1, SR=1, TNF=1)
  Type Length: 01
  Payload Length: ?? (calculated)
  Type: 55 ('U')
  URI ID: 04 (https://)
  URI: api.guideapparel.com/tap?uid=00000000000000&ctr=000000&mac=0000000000000000

Full NDEF message = D1 01 [PL] 55 04 [URI bytes...]
```

**NDEF file format:**
```
Byte 0-1: Length (big-endian, e.g., 00 4B for 75 bytes)
Byte 2+:  NDEF message
```

### Step 2: Select Application and File

Same as reading:
1. SELECT NDEF application (AID = D2 76 00 00 85 01 01)
2. SELECT File 2 (ID = E104)

### Step 3: Write Data with UPDATE BINARY

NDEF data can be large, so we write in chunks (max 255 bytes per command).

**First Chunk (bytes 0-254):**
```
APDU: 00 D6 00 00 FF [255 bytes of data]

Breaking down:
  00 = CLA
  D6 = INS (UPDATE BINARY)
  00 00 = P1 P2 (offset = 0x0000)
  FF = Lc (255 bytes of data)
  [data] = 255 bytes
  (no Le)
```

**Response:**
```
SW: 90 00 (SUCCESS)
```

**Second Chunk (bytes 255-...):**

If we have more data, continue with offset incremented:

```
APDU: 00 D6 00 FF [remaining bytes length] [data]

Breaking down:
  00 = CLA
  D6 = INS
  00 FF = P1 P2 (offset = 0x00FF = 255)
  [Lc] = length of remaining data
  [data] = remaining bytes
```

**Response:**
```
SW: 90 00 (SUCCESS)
```

### Step 4: What Happens When SDM is Enabled

If SDM is enabled (FileOption bit 6 = 1):
- File 2 becomes **read-only**
- UPDATE BINARY returns `SW = 6982` (security not satisfied)
- Even with authentication, plain UPDATE BINARY won't work

**This is why we need the disable → write → re-enable workflow when SDM is enabled!**

---

## Summary: Command Flow

### GetFileSettings (Plain)
```
→ 90 F5 00 00 01 02 00
← 00 00 E0 EE 00 00 00 [91 00]
```

### ChangeFileSettings (Secure)
```
1. Authenticate with key slot 0
2. Build secure APDU with encrypted data + MAC
   → 90 5F 00 00 19 02 [encrypted 16 bytes] [MAC 8 bytes] 00
3. Receive and validate response MAC
   ← [MAC 8 bytes] [91 00]
4. Increment command counter
```

### Read NDEF
```
1. SELECT NDEF app
   → 00 A4 04 00 07 D2 76 00 00 85 01 01 00
   ← [91 00]

2. SELECT File 2
   → 00 A4 00 0C 02 E1 04
   ← [91 00]

3. READ BINARY
   → 00 B0 00 00 FF
   ← [NDEF data up to 255 bytes] [90 00]
```

### Write NDEF (when SDM disabled)
```
1. SELECT NDEF app
2. SELECT File 2
3. UPDATE BINARY (chunk 1)
   → 00 D6 00 00 FF [255 bytes]
   ← [90 00]
4. UPDATE BINARY (chunk 2, if needed)
   → 00 D6 00 FF [Lc] [remaining bytes]
   ← [90 00]
```

### Key Differences: Plain vs Secure

**Plain Command:**
- Direct APDU to card
- No encryption
- No MAC
- Fast, simple
- Only works if access rights allow (key = 0xE)

**Secure Command:**
- Requires prior authentication
- Data is encrypted (AES-128 CBC)
- MAC is calculated and verified (AES CMAC)
- Command counter increments
- Protects confidentiality and integrity
- Required for restricted operations

---

## Why Le=0x00 Works for GetFileSettings

The NTAG 424 DNA expects Le to match the response size:
- When SDM disabled: response is 7 bytes
- When SDM enabled: response is 10+ bytes

Specific Le values (0x20, 0x10, etc.) fail because:
- Le=0x20 means "I expect exactly 32 bytes"
- Tag has only 7 bytes to return
- Tag returns 917E (LENGTH_ERROR)

Le=0x00 means:
- "Return up to 256 bytes"
- Tag can return 7 bytes (within range)
- Tag returns 9100 (SUCCESS)

This is a quirk of the NTAG 424 DNA implementation!
