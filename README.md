# NFC Tools

A collection of command-line tools for managing NTAG 424 DNA NFC tags, built with a shared Go library for DESFire EV2/EV3 operations.

## Project Structure

This is a Go workspace (`go.work`) containing:

### Shared Library
- **`pkg/ntag424`** - Core library implementing NTAG 424 DNA / DESFire EV2 protocol
  - EV2First authentication
  - Secure messaging (SSM)
  - File operations (read, write, settings)
  - Key management
  - SDM (Secure Dynamic Messaging) support
  - Structured logging via `log/slog`

### Command-Line Tools
- **`sdmconfig`** - Configure SDM settings on NTAG 424 DNA tags
  - Enable/disable SDM
  - Update NDEF templates
  - Manage file settings and access rights

- **`ro`** - Read-only diagnostic tool
  - Display tag version, UID, and capabilities
  - Read NDEF messages
  - Verify SDM URLs
  - Probe authentication slots

- **`newekey`** - Provision new tags with custom keys
  - Initialize tags from factory defaults
  - Set all application keys
  - Configure SDM settings

- **`keyswap`** - Interactive key replacement tool
  - Replace keys in specific slots
  - Uses TUI for key selection

- **`permissionsedit`** - Interactive file permissions editor
  - Modify file access rights (AR1/AR2)
  - Update SDM configuration
  - Uses TUI for settings selection

## What is go.work?

This project uses [Go workspaces](https://go.dev/doc/tutorial/workspaces), introduced in Go 1.18, which allows multiple Go modules to be developed together in a single repository.

The `go.work` file tells Go to treat all listed directories as part of the same workspace. This means:
- Changes to `pkg/ntag424` are immediately available to all tools
- No need to publish/version the shared library during development
- Simplified dependency management across modules

The workspace contains these modules:
```
./pkg/ntag424          # Shared library
./sdmconfig            # SDM configuration tool
./ro                   # Read-only diagnostic tool
./newekey              # Tag provisioning tool
./keyswap              # Key replacement tool
./permissionsedit      # Permissions editor tool
```

## Building

Each tool is built independently:

```bash
cd sdmconfig && go build .
cd ro && go build .
cd newekey && go build .
cd keyswap && go build .
cd permissionsedit && go build .
```

Or build all tools at once:
```bash
for d in sdmconfig ro newekey keyswap permissionsedit; do
  (cd "$d" && go build .)
done
```

## Key File Setup

All tools require AES-128 key files stored in the `keys/` directory. Each key file contains a 32-character hexadecimal string.

### Required Keys

Create these key files in `keys/`:
- `AppMasterKey.hex` - Application master key (KeyNo 0)
- `SDMEncryptionKey.hex` - SDM encryption key (KeyNo 1)
- `FileTwoWrite.hex` - File 2 write key (KeyNo 2)

Example:
```bash
echo "00112233445566778899AABBCCDDEEFF" > keys/AppMasterKey.hex
```

For random keys:
```bash
openssl rand -hex 16 > keys/MyKey.hex
```

**Security**: Key files are excluded from version control via `.gitignore`.

## Logging

All tools support structured logging via `log/slog` (Go 1.21+ stdlib):

### Debug Logging
```bash
./sdmconfig -v                    # Enable debug logging
./ro -v                           # Enable debug logging
./newekey -v                      # Enable debug logging
```

### JSON Logging
```bash
./sdmconfig -log-format json      # JSON output to stderr
./ro -log-format json -v          # JSON debug logs
```

### Log Levels
- **Info** (default): Authentication results, workflow progress
- **Debug** (`-v`): APDU commands, session keys, secure messaging details, retry logic
- **Warn**: Automatically logged for retry/fallback operations (e.g., wrong Le, auth fallback, plain→secure GetFileSettings)

### Changing Log Level

There are two ways to control logging:

**1. Command-line flags** (recommended):
```bash
./sdmconfig          # Info level (default)
./sdmconfig -v       # Debug level
```

**2. Programmatic control** (for advanced users):

The tools use Go's `log/slog` standard library. To customize logging beyond the built-in flags, you can:

- Modify the tool's `main()` function to use a custom handler
- Set different log levels for different components
- Add custom log attributes or filtering

Example custom handler in `main()`:
```go
import "log/slog"

// In main(), replace the default setup with:
handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
    Level: slog.LevelWarn,  // Show only warnings and errors
    AddSource: true,         // Include source file:line
})
slog.SetDefault(slog.New(handler))
```

### Log Output
- Logs are written to **stderr**
- User-facing output (UID, file settings, etc.) goes to **stdout**
- This separation allows piping stdout while preserving debug logs

Example:
```bash
# Save tag info to file, debug logs to console
./ro -v > tag_info.txt

# Debug logs with timestamps in JSON
./sdmconfig -v -log-format json 2> debug.log

# Suppress all logs except errors (requires code modification)
# Edit main() to set Level: slog.LevelError
```

## Versioning

The shared library (`pkg/ntag424`) uses git tags for versioning:

```bash
git tag pkg/ntag424/v1.0.0
git push origin pkg/ntag424/v1.0.0
```

Tools can then reference specific versions:
```go
require github.com/barnettlynn/nfctools/pkg/ntag424 v1.0.0
```

During development, the workspace ensures all tools use the local version.

## Tool Usage Examples

### Configure SDM
```bash
./sdmconfig/sdmconfig -v
./sdmconfig/sdmconfig -disable-sdm
./sdmconfig/sdmconfig -enable-sdm
```

### Read Tag Info
```bash
./ro/ro -v
./ro/ro -auth-key-file keys/AppMasterKey.hex
```

### Provision New Tag
```bash
./newekey/newekey -url https://example.com/tap
```

### Replace a Key
```bash
./keyswap/keyswap
```

### Edit Permissions
```bash
./permissionsedit/permissionsedit
```

## Requirements

- Go 1.21 or later (for `log/slog` support)
- PC/SC-compatible NFC reader
- NTAG 424 DNA tags

## Platform Support

- **macOS**: Uses Apple's native PC/SC framework
- **Linux**: Requires `pcscd` (PC/SC daemon)
- **Windows**: Uses Windows PC/SC APIs

## License

[License TBD]

## Contributing

This is a personal project for managing NTAG 424 DNA tags. Contributions are welcome!
