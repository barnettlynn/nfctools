# New Key Tool Notes

This tool provisions a new NTAG 424 DNA tag with your key set and configures SDM/NDEF.

## Run
From `newekey/`:

```bash
go run .
```

Optional example with explicit URL and reader:

```bash
go run . -url https://api.guideapparel.com/tap -reader 0
```

## Flags
- `-app-master-key-file` Path to AppMasterKey file (KeyNo 0, default: `../keys/AppMasterKey.hex`).
- `-sdm-key-file` Path to SDM key file (KeyNo 1, default: `../keys/SDMEncryptionKey.hex`).
- `-ndef-key-file` Path to File Two Write key file (KeyNo 2, default: `../keys/FileTwoWrite.hex`).
- `-url` Base URL for SDM NDEF (default: `https://api.guideapparel.com/tap`).
- `-reader` Reader index (default: `0`).
- `-auth-key` Optional 32-hex auth key (default: all zeroes).
- `-auth-keyno` Auth key number (default: `0`).

## Key Steps
- Authenticate (EV2First) with the current configuration key (default KeyNo 0, often all-zero).
- Change keys: Key 0 -> `../keys/AppMasterKey.hex` (AppMasterKey).
- Change keys: Key 1 -> `../keys/SDMEncryptionKey.hex` (SDM key).
- Change keys: Key 2 -> `../keys/FileTwoWrite.hex` (File Two Write key).
- Re-authenticate with the new Key 0.
- ChangeFileSettings on file 2: enable SDM and set offsets for UID/CTR/MAC.
- ChangeFileSettings on file 2: set SDMAccessRights to use Key 1 for MAC and counter return.
- ChangeFileSettings on file 2: lock File Two Write to Key 2 (W=2).
- Write the SDM URL template: `https://api.guideapparel.com/tap?uid=...&ctr=...&mac=...`

## Defaults Used By This Tool
- AccessRights: `E0 E2` (RW=E, CAR=0, R=E, W=2)
- SDMOptions: `0xC1` (UID + ReadCtr, ASCII on, EncFile off)
- SDMAccessRights: `Meta=E`, `File=1`, `CtrRet=1`
- Offsets are derived from the URL template and match the C tool.

## Important Bug Fix (Bit-Shift in SDM AR)
We hit a critical Go bug while building SDMAccessRights (`sdmAR`) that caused invalid
ChangeFileSettings MACs and `SW=917E` responses.

**Root cause**
- In Go, shifting a `byte` (uint8) by 8 or 12 drops the high bits.
- The old code built `sdmAR` using byte shifts, so:
  - Expected: `sdmAR = 0xE1F1`
  - Actual (broken): `sdmAR = 0x00F1`
- This changed the plaintext, the encrypted data, and the MAC — the tag rejected it.

**Fix**
Cast to `uint16` before shifting:

```go
sdmAR := uint16((uint16(sdmMeta&0x0F) << 12) |
	(uint16(sdmFile&0x0F) << 8) |
	(0x0F << 4) |
	uint16(sdmCtr&0x0F))
```

This made the Go ChangeFileSettings APDU match the C tool and the tag accepted it.
