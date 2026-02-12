# SDM Workflows

This tool provides three workflow modes for managing SDM (Secure Dynamic Messaging) on NTAG 424 DNA tags.

## Usage

```bash
go run . [--disable-sdm | --enable-sdm | --update-sdm]
```

## Workflows

### 1. Disable SDM (`--disable-sdm`)

Disables SDM on the tag and sets the file to allow free writes.

**When to use:** When you need to disable SDM features or prepare the tag for manual NDEF updates.

**What it does:**
- Authenticates with settings key (slot 0)
- Sets FileOption=0x00 (SDM disabled)
- Sets AR2=0xEE (free write access)
- Preserves AR1 (change settings still requires slot 0)

**Example:**
```bash
go run . --disable-sdm
```

### 2. Enable SDM (`--enable-sdm`)

Writes the NDEF template and enables SDM.

**When to use:** When SDM is currently disabled and you want to enable it with a new NDEF URL.

**Prerequisites:**
- SDM must currently be disabled
- File must have free write access (AR2=0xEE)

**What it does:**
- Writes NDEF template using plain (unauthenticated) writes
- Authenticates with settings key (slot 0)
- Enables SDM with SDMOptions=0xC1
- Restores original access rights (AR2=0x22)
- Configures SDM offsets for UID, counter, and MAC

**Example:**
```bash
# First disable SDM if needed
go run . --disable-sdm

# Then enable with new URL
go run . --enable-sdm
```

### 3. Update SDM (`--update-sdm`)

Full workflow to update NDEF content when SDM is already enabled.

**When to use:** When SDM is currently enabled and you need to update the NDEF URL template.

**What it does:**
- **Step 1:** Disables SDM and sets free write access
- **Step 2:** Writes new NDEF template
- **Step 3:** Re-enables SDM with original access rights

**Example:**
```bash
go run . --update-sdm
```

This is equivalent to:
```bash
go run . --disable-sdm
# NDEF write happens automatically
go run . --enable-sdm
```

## Normal Operation

Without workflow flags, the tool operates in standard mode:

```bash
go run .  # Normal mode
```

**Standard mode** (from config.yaml):
- `settings_only: false` - Updates both settings and NDEF
- `settings_only: true` - Updates only SDM settings, skips NDEF write
- `force_plain: true` - Skips ChangeFileSettings command

## Configuration

All workflows use `config.yaml`:

```yaml
url: "https://api.guideapparel.com/tap"

sdm:
  file_no: 2
  sdm_key_no: 1

auth:
  settings_key_no: 0
  settings_key_hex_file: "../keys/AppMasterKey.hex"
  file2_write_key_no: 2  # Not used in workflows (uses free writes)
  file2_write_key_hex_file: "../keys/FileTwoWrite.hex"

runtime:
  reader_index: 0
  settings_only: false
  force_plain: false
```

## Diagnostics

Test authentication across all key slots:

```bash
go run . --diag-auth
```

Enable debug output for secure messaging APDUs:

```bash
go run . --update-sdm --debug-apdu
```

## Technical Notes

### Why Free Writes?

The workflows use **free write access (AR2=0xEE)** during NDEF updates because:

1. When SDM is enabled, File 2 becomes read-only
2. Plain UPDATE BINARY commands don't support authenticated writes
3. Setting AR2=0xEE temporarily allows plain writes
4. Access rights are restored when SDM is re-enabled

### Access Rights Encoding

- **AR1** (byte): `[Read+Write key (4 bits)][Change settings key (4 bits)]`
- **AR2** (byte): `[Read key (4 bits)][Write key (4 bits)]`

**Example:** AR1=0x20, AR2=0xE2
- Read: free (0xE)
- Write: slot 2
- Read+Write: slot 2
- Change settings: slot 0

**Free access:** 0xE (14) = no authentication required

### SDM Options

**SDMOptions=0xC1:**
- Bit 7 (0x80): UID mirroring enabled
- Bit 6 (0x40): Counter mirroring enabled
- Bit 0 (0x01): Tag tamper status enabled

## Troubleshooting

### "GetFileSettings error: SW=917E"

This warning appears because GetFileSettings fails with a length error. The tool falls back to hard-coded access rights (AR1=0x20, AR2=0x22). This doesn't affect workflow functionality but will be investigated.

### "Write NDEF failed: SW=6982"

**Cause:** Security status not satisfied - file requires authentication.

**Solution:** Use the appropriate workflow:
- If SDM is enabled: `--update-sdm`
- If SDM is disabled: `--enable-sdm`

### "ChangeFileSettings failed: SW=919E"

**Cause:** Invalid parameters in ChangeFileSettings command.

**Solution:** Check that SDM is in the expected state. Use `--diag-auth` to verify key configuration.
