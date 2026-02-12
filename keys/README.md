# Key Files

This directory contains AES-128 key files used by the NFC tools.

## Format

Each `.hex` file contains a single 32-character hexadecimal string representing a 16-byte AES-128 key.

Example:
```
00112233445566778899AABBCCDDEEFF
```

## Security

**IMPORTANT**: Never commit actual key files to version control. The `.gitignore` file excludes all `.hex` files in this directory.

## Key Types

Common key files:
- `AppMasterKey.hex` - Application master key (KeyNo 0)
- `SDMEncryptionKey.hex` - SDM encryption key (KeyNo 1)
- `FileTwoWrite.hex` - File 2 write key (KeyNo 2)
- `FileTwoRead.hex` - File 2 read key (KeyNo 14)
- `FileThreeWrite.hex` - File 3 write key

## Creating Key Files

To create a new key file:
```bash
echo "00112233445566778899AABBCCDDEEFF" > keys/MyKey.hex
```

For random keys:
```bash
openssl rand -hex 16 > keys/RandomKey.hex
```
