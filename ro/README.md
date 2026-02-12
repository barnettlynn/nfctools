# Reader Tool Notes

This tool waits for tag scans, prints UID and NDEF data, decodes the URI record,
verifies SDM MACs from the URL parameters when present, and checks provisioning
against keys in `../keys/` (with a fallback check for factory defaults).

## Run
From `ro/`:

```bash
go run .
```

Select a specific reader by index:

```bash
go run . 1
```

Select a reader by substring match:

```bash
go run . ACR122U
```

## Arguments
- `<reader>` Optional. Either a numeric index (0-based) or a substring of the reader name.

## Flags
- `-auth-key-file` Path to AppMasterKey file (KeyNo 0, default: `../keys/AppMasterKey.hex`).
- `-auth-key` Optional 32-hex auth key.
- `-auth-keyno` Auth key number (default: `0`).
- `-sdm-key-file` Path to SDM key file (KeyNo 1, default: `../keys/SDMEncryptionKey.hex`).
- `-sdm-key` Optional 32-hex SDM key.
- `-sdm-keyno` SDM key number (default: `1`).
- `-file` File number for SDM settings (default: `2`).
