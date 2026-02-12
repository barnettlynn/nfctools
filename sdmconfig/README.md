# Update Tool

CLI for updating SDM settings and NDEF URL template on an existing NTAG 424 DNA tag.

This tool does **not** rotate keys. It uses configured keys for authentication only.

## Run
From `update/`:

```bash
go run .
```

Optional debug output:

```bash
go run . -debug-apdu
```

Run EV2 auth diagnostics (slot sweep using settings key file):

```bash
go run . -diag-auth
```

## CLI Flags
- `-debug-apdu` Print secure messaging APDUs
- `-diag-auth` Try EV2 auth on slots `0..15` with the configured settings key and exit

The tool loads `config.yaml` from the executable directory. If not found there (for example with `go run`), it falls back to `./config.yaml` in the current working directory.

## Config File
Use `config.example.yaml` as template.

```yaml
url: "https://api.guideapparel.com/tap"

sdm:
  file_no: 2
  sdm_key_no: 1

auth:
  settings_key_no: 0
  settings_key_hex_file: "../keys/AppMasterKey.hex"
  file2_write_key_no: 2
  file2_write_key_hex_file: "../keys/FileTwoWrite.hex"

runtime:
  reader_index: 0
  settings_only: false
  force_plain: false
```

## Required Config Fields (Normal Run)
- `url`: Absolute URL for SDM NDEF template
- `sdm.file_no`: File number to update (`0..31`)
- `sdm.sdm_key_no`: SDM key slot used in SDM access rights (`0..15`)
- `auth.settings_key_no`: Key slot used to authenticate for `ChangeFileSettings` (`0..15`)
- `auth.settings_key_hex_file`: Key file for settings auth (32 hex chars)
- `auth.file2_write_key_no`: Key slot used to authenticate before writing File 2 (`0..15`)
- `auth.file2_write_key_hex_file`: Key file for File 2 write auth (32 hex chars)
- `runtime.reader_index`: PC/SC reader index (`>=0`)
- `runtime.settings_only`: Skip NDEF write when `true`
- `runtime.force_plain`: Skip ChangeFileSettings when `true`

## Diagnostic Mode Requirements
For `-diag-auth`, only these are required:
- `auth.settings_key_no`
- `auth.settings_key_hex_file`
- `runtime.reader_index`

## Behavior
1. Load and validate config.
2. Build SDM URL template and offsets.
3. Authenticate using `auth.settings_*`.
4. Read current file settings and preserve existing access-right nibbles.
5. If settings read fails, fallback to `AR1=0x20`, `AR2=0x22` with a high-visibility warning banner in logs.
6. Apply SDM file settings (unless `runtime.force_plain=true`).
7. Authenticate using `auth.file2_write_*`.
8. Write NDEF template (unless `runtime.settings_only=true`).
9. Re-authenticate using `auth.settings_*` for final settings read.

## EV2 Auth Notes
`auth step2 failed (SW=91AE len=0)` usually indicates a key/slot mismatch.

For cards where File 2 change settings is under slot 0 and File 2 write is under slot 2:
- `auth.settings_key_no` should be `0` with `AppMasterKey`
- `auth.file2_write_key_no` should be `2` with `FileTwoWrite` key

## Tests
Run all tests:

```bash
go test ./...
```
