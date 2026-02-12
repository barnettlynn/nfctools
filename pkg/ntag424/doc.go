/*
Package ntag424 provides a unified library for communicating with NXP NTAG 424 DNA tags.

This package consolidates the core functionality previously duplicated across five tools
(ro, update, newekey, keyswap, permissionsedit), providing:
  - Cryptographic operations (AES-CBC, AES-CMAC, DESFire session key derivation)
  - EV2First authentication with session management
  - Secure messaging (BuildSsmApdu, SsmCmdFull)
  - File settings read/modify (GetFileSettings, ChangeFileSettings)
  - Read operations (ISO READ BINARY, DESFire ReadData, NDEF reads)
  - Key management (loading, changing keys with CRC32 versioning)
  - SDM (Secure Dynamic Messaging) configuration and verification
  - PC/SC card connection wrapper

# Access Rights Encoding

Per the DESFire specification, the 16-bit access rights value is organized (MSB→LSB) as:

	[Read | Write | ReadWrite | ChangeAccessRights]
	bits 15-12: Read key
	bits 11-8:  Write key
	bits 7-4:   ReadWrite key
	bits 3-0:   ChangeAccessRights key

These are stored **little-endian** in the GetFileSettings response at byte offsets 2-3:

	Byte offset 2 (AR1) = LSB: [ReadWrite nibble | ChangeAccessRights nibble]
	Byte offset 3 (AR2) = MSB: [Read nibble      | Write nibble]

Nibble values:

	0x0-0xD = key slot number (authenticate with that key to perform operation)
	0xE     = free (no authentication needed)
	0xF     = denied (operation never permitted)

Example: AR1=0x20, AR2=0xE2

	Read:               0xE (free)    ← AR2 upper nibble (bits 15-12)
	Write:              0x2 (slot 2)  ← AR2 lower nibble (bits 11-8)
	ReadWrite:          0x2 (slot 2)  ← AR1 upper nibble (bits 7-4)
	ChangeAccessRights: 0x0 (slot 0)  ← AR1 lower nibble (bits 3-0)

# File Map

NTAG 424 DNA tags have three application files after SelectNDEFApp (AID 0xD2760000850101):

File 1 (ID 0xE103) — Capability Container (CC)

	Size: 32 bytes. Type: standard data.
	Default AR: Read=free, Write=slot 0, RW=slot 0, CAR=slot 0
	Always readable via plain ISO READ BINARY (INS 0xB0).

File 2 (ID 0xE104) — NDEF File

	Size: 256 bytes. Type: standard data.
	Provisioned AR: Read=free, Write=slot 2, RW=slot 2, CAR=slot 0
	Readable via plain ISO READ BINARY when Read=free.
	When SDM enabled: tag dynamically inserts UID, counter, MAC into URL on each read.

File 3 (ID 0xE105) — Proprietary Data

	Size: 128 bytes. Type: standard data.
	Default AR: Read=slot 0, Write=slot 0, RW=slot 0, CAR=slot 0
	Usually requires authentication to read.

# Operation: GetFileSettings (INS 0xF5)

Purpose: Read a file's type, comm mode, access rights, size, and SDM configuration.
Required access: ChangeAccessRights key OR free.

Plain mode (CAR=free or CommMode=plain):

	Command:  90 F5 00 00 01 <fileNo> 00
	Response: <FileType(1)> <FileOption(1)> <AR1(1)> <AR2(1)> <Size(3)> [SDM fields...] | SW

	Le MUST be 0x00 (wildcard) — specific Le values cause SW=917E.

MAC mode (CommMode=MAC):

	Command:  90 F5 00 00 <Lc> <fileNo> <MAC(8)> 00
	Response: <data> <MAC(8)> | SW

	Data is cleartext but MACed for integrity.

Full mode (CommMode=Full, after EV2First auth):

	Command:  90 F5 00 00 <Lc> <fileNo> <MAC(8)> 00
	Response: <EncData> <MAC(8)> | SW

	Data encrypted with session Kenc, MACed with Kmac.

Response fields (when SDM disabled, 7 bytes):

	[0]   FileType    0x00=standard data
	[1]   FileOption  bit 6=SDM, bits 1:0=CommMode
	[2]   AR1         [RW nibble | CAR nibble]
	[3]   AR2         [R nibble  | W nibble]
	[4:6] Size        3-byte little-endian

Additional fields (when SDM enabled, 10+ bytes):

	[7]   SDMOptions  bit7=UID mirror, bit6=Ctr mirror, bit0=TT
	[8:9] SDMAR       little-endian uint16: [Meta(15:12)|File(11:8)|RFU(7:4)|Ctr(3:0)]
	[10+] Offsets     conditional 3-byte LE offsets (UID, Ctr, MACInput, MAC, ENC)

Fail states:

	SW=917E  Le wrong (use Le=0x00), or file doesn't exist
	SW=91AE  Auth failed (wrong key for the slot)
	SW=6982  Security not satisfied (need auth but no session)

# Operation: ReadData (INS 0xBD) — DESFire Native

Purpose: Read file data using DESFire native command.
Required access: Read key OR ReadWrite key.

Plain mode (Read=free):

	Command:  90 BD 00 00 07 <fileNo> <offset(3)LE> <length(3)LE> 00
	Response: <data> | SW

Full mode (after EV2First auth with Read key slot):

	Via SsmCmdFull: encrypts command data, header=nil, data=[fileNo,off(3),len(3)]
	Command:  90 BD 00 00 <Lc> <EncData(16+)> <MAC(8)> 00
	Response: <EncData> <MAC(8)> | SW

	SsmCmdFull handles: IV generation, encryption, MAC, response verification, decryption.

Fail states:

	SW=6982  Auth required but no session (Read != free)
	SW=911C  Boundary error: offset+length > file size. Treat as empty file.
	SW=917E  Length error (bad command format)
	SW=91AE  Auth error (wrong key)

	Response MAC mismatch → re-authenticate and retry

# Operation: ISO READ BINARY (INS 0xB0) — For NDEF/CC

Purpose: Read file data via ISO 7816 after SELECT FILE.
Required access: Read=free (ISO commands don't carry DESFire auth).

Command:

	00 B0 <offset_hi> <offset_lo> <Le>

Response:

	<data> | SW

Chunking: Max 255 bytes per read. Loop with increasing offset.
NDEF format: First 2 bytes = NLEN (big-endian length), then NDEF message.

Fail states:

	SW=6C00+xx  Wrong Le → retry with Le=SW2 (correct length in low byte)
	SW=6982     Security not satisfied (Read != free, need DESFire auth instead)
	SW=6A82     File not found (wrong file ID or not selected)
	SW=6A86     Wrong P1P2 (offset beyond file)

Note: ISO READ BINARY CANNOT use DESFire secure messaging.
If Read requires authentication, use ReadData (0xBD) via SsmCmdFull instead.

# Operation: ChangeFileSettings (INS 0x5F)

Purpose: Modify file's comm mode, access rights, and SDM configuration.
Required access: ChangeAccessRights key. ALWAYS uses secure messaging.

Basic format (SDM disabled, 3 bytes plaintext → encrypted):

	Data: <FileOption(1)> <AR1(1)> <AR2(1)>
	Via SsmCmdFull: header=[fileNo], data=[FileOption,AR1,AR2]

SDM format (SDM enabled, variable length):

	Data: <FileOption(1)> <AR1(1)> <AR2(1)> <SDMOptions(1)> <SDMAR(2)> [offsets...]

	Offsets are conditional:
	  UIDOffset(3)      if SDMOptions.bit7 AND SDMMeta=0xE
	  CtrOffset(3)      if SDMOptions.bit6 AND SDMMeta=0xE
	  MACInputOffset(3) if SDMFile != 0xF
	  MACOffset(3)      if SDMFile != 0xF

Fail states:

	SW=917E  Wrong data length (mismatch between SDMOptions and included offsets)
	SW=919E  Invalid parameter (bad offset values or conflicting settings)
	SW=9140  No changes (settings identical to current)
	SW=91AE  Auth error (wrong CAR key)
	SW=6982  Security not satisfied

# Operation: AuthenticateEV2First (INS 0x71 + 0xAF)

Purpose: Establish encrypted session with the tag.
Two-phase handshake:

Phase 1:

	Command:  90 71 00 00 02 <keyNo> 00 00
	Response: <EncRndB(16)> | SW=91AF

Phase 2:

	Decrypt RndB, generate RndA, send encrypted RndA||RotateLeft(RndB)
	Command:  90 AF 00 00 20 <Enc(RndA||RndB')(32)> 00
	Response: <Enc(TI||RndA')(32)> | SW=9100

Session derivation:

	SV1 = A5 5A 00 01 00 80 || rndA[0:2] || (rndA[2:8] XOR rndB[0:6]) || rndB[6:16] || rndA[8:16]
	SV2 = 5A A5 00 01 00 80 || (same fill)
	Kenc = AES-CMAC(key, SV1)
	Kmac = AES-CMAC(key, SV2)

Fail states:

	SW=91AE  Wrong key for slot (most common)
	SW=917E  Bad command format

	rndA verification failed = key mismatch (decryption produced wrong RndA')

CRITICAL: SelectNDEFApp or SelectFile INVALIDATES the session.
Always select BEFORE authenticating, or re-authenticate after selecting.

# SDMOptions Byte

	Bit 7 (0x80): UID mirroring enabled
	Bit 6 (0x40): Read counter mirroring enabled
	Bit 5:        Reserved
	Bit 4 (0x10): SDM ENC file data encryption
	Bit 3:        Reserved
	Bit 2:        Reserved
	Bit 1:        Reserved
	Bit 0 (0x01): Tag tamper status enabled

Common value: 0xC1 = UID mirror + Counter mirror + Tag tamper

# Communication Modes

Three modes (bits 1:0 of FileOption byte):

	0x00 Plain: No security. Data in cleartext. Commands use CLA=0x00 (ISO) or CLA=0x90 (DESFire native).
	0x01 MAC:   Integrity only. Response includes 8-byte truncated CMAC. Data readable in cleartext.
	0x03 Full:  Confidentiality + integrity. Data encrypted with AES-CBC, response includes CMAC. Requires active EV2 session.

Each file's **actual** comm mode for a given operation depends on **both** the FileOption comm mode bits AND the access rights.
If Read=0xE (free), the tag serves data in plain regardless of FileOption.

# Complete Fail State Reference

ISO 7816 Status Words:

	SW=9000  Success
	SW=6982  Security status not satisfied (need auth)
	SW=6A82  File not found
	SW=6A86  Incorrect P1/P2 (wrong parameters)
	SW=6C00  Wrong Le (correct Le in SW2 low byte)
	SW=6700  Wrong length

DESFire Status Words:

	SW=9100  Success (operation complete)
	SW=91AF  Additional frame expected (send 90 AF to continue)
	SW=917E  Length error (wrong Le, bad fileNo, or format error)
	SW=91AE  Authentication error (wrong key for slot)
	SW=919D  Permission denied (authenticated but insufficient rights)
	SW=919E  Parameter error (invalid settings data)
	SW=911C  Command not allowed / boundary error (read past file end)
	SW=9140  No changes (settings already match)
	SW=91CA  Command aborted (general failure)

Session/Crypto Errors:

	Response MAC mismatch    Session corrupted or MITM. Re-authenticate.
	rndA verification failed Key mismatch during EV2First. Check key file.
	Bad padding              Decrypted response has invalid ISO 9797 M2 padding.
	APDU data too long       Command data exceeds 255 bytes. Chunk the operation.
*/
package ntag424
