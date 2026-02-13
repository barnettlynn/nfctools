# Emulator: NFC Tag Tap Simulator

The emulator tool simulates what an NTAG 424 DNA tag does internally when tapped: it fills in the UID and read counter, computes the CMAC, and produces the final SDM URL that a phone would receive.

This enables offline testing and development without requiring a physical NFC tag and reader.

## Usage

```bash
./emulator -uid <UID> [options]
```

### Required Flags

- `-uid` — 14-character hex string representing the 7-byte tag UID (e.g., `04A47A8A123456`)

### Optional Flags

- `-ctr` — SDM read counter value (default: `0`, max: `16777215` / `0xFFFFFF`)
- `-sdm-key-file` — Path to SDM encryption key file (default: `../keys/SDMEncryptionKey.hex`)
- `-url` — Base URL for the SDM endpoint (default: `https://api.guideapparel.com/tap`)
- `-verify` — Self-verify the generated URL using `VerifySDMMAC` (default: `false`)
- `-v` — Enable debug logging (default: `false`)
- `-log-format` — Log format: `text` or `json` (default: `text`)

## Examples

### Basic usage

```bash
./emulator -uid 04A47A8A123456
```

Output:
```
SDM key: ../keys/SDMEncryptionKey.hex
UID:     04A47A8A123456
Counter: 0
URL:     https://api.guideapparel.com/tap?ctr=000000&mac=A5272961036126CE&uid=04A47A8A123456
```

### With counter and verification

```bash
./emulator -uid 04A47A8A123456 -ctr 42 -verify
```

Output:
```
SDM key: ../keys/SDMEncryptionKey.hex
UID:     04A47A8A123456
Counter: 42
URL:     https://api.guideapparel.com/tap?ctr=00002A&mac=F78CC28956C08341&uid=04A47A8A123456
Verify:  OK
```

### Custom URL with existing parameters

```bash
./emulator -uid 04A47A8A123456 -url "https://example.com/tap?product=abc123"
```

The tool preserves existing query parameters in the URL.

### Debug logging

```bash
./emulator -uid 04A47A8A123456 -ctr 1 -v
```

Enables detailed logging showing key loading, UID parsing, and MAC computation.

### JSON logging

```bash
./emulator -uid 04A47A8A123456 -ctr 1 -v -log-format json
```

Outputs structured JSON logs for integration with log aggregation systems.

## How It Works

The emulator performs the same cryptographic operations as a physical NTAG 424 DNA tag:

1. **Load SDM key** — Reads the 16-byte AES key from the specified hex file
2. **Parse UID** — Converts the 14-character hex UID string to 7 bytes
3. **Encode counter** — Converts the counter value to 3-byte big-endian hex (6 chars)
4. **Derive session key** — Uses `DeriveSDMSessionKey` with UID and counter (little-endian)
5. **Compute CMAC** — Calculates AES-CMAC over `"uid=<UID>&ctr=<CTR>&mac="`
6. **Truncate MAC** — Extracts odd bytes only (8 bytes total, 16 hex chars)
7. **Build URL** — Appends `uid`, `ctr`, and `mac` query parameters to base URL

If `-verify` is set, the tool validates the generated URL using `VerifySDMMAC` to ensure round-trip correctness.

## Building

```bash
go build
```

## Testing

Run with verification to confirm the implementation:

```bash
./emulator -uid 04A47A8A123456 -ctr 1 -verify
```

Expected output should end with `Verify:  OK`.
