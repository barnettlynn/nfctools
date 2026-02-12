# NTAG 424 DNA Concepts Guide

A comprehensive guide to understanding NFC tags, security, and the provisioning system.

---

## 🏠 **The Building Analogy**

Think of your **NTAG 424 DNA tag** as a small office building with different rooms and security systems.

---

## Basic Components

### **UID (Unique Identifier)**
- **What**: `044576A2842090` - like a serial number burned into the chip
- **Analogy**: The building's street address - permanent, can't be changed
- **Purpose**: Uniquely identifies this specific tag

### **NFC Reader (ACS ACR122U)**
- **What**: The device connected to your computer that communicates with tags
- **Analogy**: A security guard's badge reader at the building entrance
- **Purpose**: Lets your computer "talk" to the tag when you tap it

### **NDEF (NFC Data Exchange Format)**
- **What**: The actual data stored on the tag - in your case, a URL
- **Analogy**: A poster hanging in the lobby that anyone can read
- **Purpose**: The public-facing information your tag shares with phones

---

## The Three Key Slots (Like Different Keys to Different Locks)

Your NTAG 424 DNA has **5 key slots** (0-4), but you're typically using 3 of them:

### **Slot 0 - AppMasterKey (Application Master Key)**
- **What**: The "master admin" key that controls permissions
- **Analogy**: The building owner's master key - can change locks, set security policies, decide who has access to what
- **Purpose**: Lets you reconfigure file permissions, change which keys control what operations
- **Security risk if default**: Like the building still having the contractor's temporary key

### **Slot 1 - SDM Key**
- **What**: The key that creates cryptographic "signatures" in the URL
- **Analogy**: The notary public's seal - proves the document is authentic and hasn't been tampered with
- **Purpose**: Generates the `mac=` parameter in your URL to prove the tag is genuine
- **Critical for security**: This is what prevents counterfeiting

### **Slot 2 - File Two Write Key**
- **What**: The key needed to change the URL/data on the tag
- **Analogy**: The key to the lobby's poster frame - controls who can change what's displayed
- **Purpose**: Prevents unauthorized people from changing the URL on your tag
- **Security risk if default**: Anyone with the all-zero key can change your URL

---

## Provisioning vs Default

### **Provisioned**
- **What**: You've replaced the factory default key with your own secret key
- **Analogy**: You've changed the locks from the builder's temporary keys to your own keys
- **Why it matters**: Security! Factory keys are published in documentation - anyone can look them up

### **Default (All-Zero Key)**
- **What**: The factory setting - a key of 16 bytes of zeros: `00000000000000000000000000000000`
- **Analogy**: Like a building still using "1234" as the door code
- **Why it's bad**: Everyone knows this key! It's in the chip's documentation
- **When it's okay**: Only during initial setup/testing - never in production

---

## SDM (Secure Dynamic Messaging) - The Cool Part

**What SDM Does**:
Your URL isn't static - it changes every time someone taps the tag:

```
https://api.guideapparel.com/tap?uid=044576A2842090&ctr=00002A&mac=096F6B5C0CF1BB57
                                                       ^^^^^^      ^^^^^^^^^^^^^^^^
                                                      counter           MAC
```

### **The Counter (`ctr=00002A`)**
- **What**: Starts at 0, increases by 1 with every tap
- **Analogy**: Like a visitor log book entry number - shows this is the 42nd tap (0x2A = 42)
- **Purpose**: Prevents "replay attacks" - someone can't copy yesterday's URL and reuse it

### **The MAC (`mac=096F6B5C0CF1BB57`)**
- **What**: A cryptographic signature calculated using the SDM key (slot 1)
- **Analogy**: Like a tamper-evident seal on a product - you can verify it's genuine
- **How it works**:
  1. Tag takes: UID + counter + your secret key (slot 1)
  2. Runs them through a cryptographic function (CMAC-AES128)
  3. Produces the MAC
  4. Your server does the same calculation and compares
- **Purpose**: Proves the tag is genuine and the data hasn't been tampered with

### **Why This Matters**:
- ✅ **Can't counterfeit**: You need the secret key to create a valid MAC
- ✅ **Can't replay**: The counter increments, so old URLs become invalid
- ✅ **Can verify**: Your server can prove the tap came from a real tag
- ✅ **No network needed**: The tag does this cryptography internally

---

## 📁 The NTAG 424 DNA File System

Think of the tag like a tiny filing cabinet with numbered folders:

### **File 1 - Capability Container (CC File)**

**What it is**: A "table of contents" or "directory" file

**Analogy**: Like the building directory in the lobby that says:
- "Floor 1: NDEF data storage"
- "Floor 2: Proprietary data"
- "Maximum capacity: 256 bytes"
- "Supports: read, write, SDM features"

**What it contains**:
- Mapping version (NDEF standard version)
- Maximum read size
- Maximum write size
- File structure information
- Pointers to other files

**Purpose**: When an NFC phone taps your tag, it reads File 1 first to understand:
- "Is this tag formatted for NDEF?"
- "Where is the actual data?"
- "What can I do with this tag?"

**Typical access**: Usually read-only or requires a key to modify

---

### **File 2 - NDEF Data File** ⭐ **(The Main Event)**

**What it is**: The actual payload - your URL

**Analogy**: The poster in the lobby with your message/URL

**What it contains**:
```
D1014C55046170692E67756964656170706172656C2E636F6D2F7461703F...
```
Which decodes to:
```
https://api.guideapparel.com/tap?uid=044576A2842090&ctr=00002A&mac=096F6B5C0CF1BB57
```

**Purpose**: This is THE file - the reason the tag exists
- Phones read this file when tapped
- SDM modifies this file dynamically (updates counter & MAC)
- Your File Two Write key controls who can change it

**Typical size**: NTAG 424 DNA has 416 bytes of usable NDEF storage

**Access rights structure**:
- **Read**: Who can read the URL
- **Write**: Who can change the URL (controlled by slot 2)
- **ReadWrite**: Combined read+write access
- **CAR (Change Access Rights)**: Who can modify these permissions (controlled by slot 0)

---

### **File 3 - Proprietary Data File**

**What it is**: A "scratch pad" file for custom data

**Analogy**: Like a private storage room in the building for tenant use

**What it's for**:
- Store additional data that ISN'T meant for phones to auto-read
- Could be:
  - Product serial numbers
  - Manufacturing data
  - Internal tracking codes
  - Encrypted configuration
  - Anything you want!

**Key difference from File 2**:
- **File 2**: NDEF formatted - phones automatically try to read and parse it
- **File 3**: Raw data - only your custom app would read it

**Purpose**: Lets you use the tag for dual purposes:
1. **Public NDEF** (File 2): Everyone can tap and get the URL
2. **Private data** (File 3): Only your app with the right keys can access it

**Typical use cases**:
- Store product authenticity tokens
- Keep encrypted ownership records
- Track manufacturing/quality data
- Store app-specific configuration

**Typical size**: ~256 bytes

---

## 🗂️ **The Complete File Structure**

```
NTAG 424 DNA
│
├── File 1 (CC File - Capability Container)
│   ├── Size: ~32 bytes
│   ├── Purpose: "Table of contents"
│   └── Access: Usually read-only
│
├── File 2 (NDEF File) ⭐
│   ├── Size: ~416 bytes usable
│   ├── Purpose: Your URL with SDM
│   └── Access: Read=free, Write=slot 2, CAR=slot 0
│
└── File 3 (Proprietary File)
    ├── Size: ~256 bytes
    ├── Purpose: Custom data storage
    └── Access: Configurable (you set the access rights)
```

---

## File Settings & Access Rights - The Permission System

**Access Rights** work like a permission matrix for each file:

| Operation | What It Controls | Example Value |
|-----------|-----------------|---------------|
| **Read data** | Who can read the file contents | `0xE` = free (anyone) |
| **Write data** | Who can modify the file contents | `0x2` = need key slot 2 |
| **Read+Write** | Combined read and write access | `0xE` = free |
| **Change settings (CAR)** | Who can change these permissions | `0x0` = need key slot 0 |

**Special Permission Values**:
- `0xE` = "Free" - no key needed (like a public restroom)
- `0xF` = "Never" - nobody can do this, ever (like a sealed wall)
- `0x0` through `0x4` = "Need key from slot N" (like needing a specific keycard)

**Example - Typical Provisioned File 2**:
```
AccessRights: E0 E2
  Read data (R):        0xE (free) - anyone can scan and get the URL
  Write data (W):       0x2 (slot 2) - need File Two Write key to change URL
  Read+Write (RW):      0xE (free) - no additional restrictions
  Change settings (CAR): 0x0 (slot 0) - need config key to modify permissions
```

---

## Authentication - Proving You Have the Right Key

### **EV2First Authentication Protocol**
- **What**: A cryptographic handshake protocol
- **Analogy**: Like showing your ID and signing your name to prove you're really you
- **How it works**:
  1. You say "I want to authenticate with slot 1"
  2. Tag sends a random challenge
  3. You encrypt it with your key
  4. Tag verifies you got it right
  5. If yes: session unlocked!
- **Purpose**: Proves you have the key without actually sending the key over the air (secure!)

### **Why This Matters**
- Someone listening to the NFC conversation can't steal your key
- Each authentication session is unique (because of the random challenge)
- The actual key never leaves your device

---

## 🔄 What Happens When a Phone Taps

**Step-by-step**:
1. **Phone**: "Hey tag, can I read you?"
2. **Tag**: "Sure! Here's **File 1** (the directory)"
3. **Phone** reads File 1: "Oh, this is an NDEF tag, the data is in **File 2**"
4. **Tag**: "Here's **File 2**" (but SDM kicks in FIRST!)
5. **SDM magic happens**:
   - Tag uses SDM key (slot 1)
   - Increments counter: 42 → 43
   - Calculates new MAC using UID + new counter + secret key
   - Rewrites the URL in File 2 with new counter & MAC
6. **Phone** receives the UPDATED URL with new counter and MAC
7. **Phone**: "This is a URL! Opening browser..."
8. **Browser** navigates to your server
9. **Your server** verifies the MAC to confirm it's a genuine tag

The phone never even knows about **File 3** unless your custom app specifically asks for it!

---

## The Provisioning Check Workflow

### **What Your Tool Does**

**Step 1: Probe Keys**
- **What**: Try authenticating with each key file against each slot
- **Analogy**: Trying different keys in different locks to see which ones open
- **Purpose**: Figure out which keys are provisioned vs still default

**Step 2: Show Key Status**
```
  Key slots:
    Slot 0 (AppMaster):  default       (all-zero key)  ⚠️
    Slot 1 (SDM):     provisioned   (SDMEncryptionKey.hex)  ✅
    Slot 2 (File Two Write):  default       (all-zero key)  ⚠️
```
Tells you at a glance: which locks have you changed, which are still factory defaults

**Step 3: Try to Read File Settings**
- **What**: Authenticate and ask the tag "what are your permission settings?"
- **Why**: To show you the complete access rights matrix
- **Challenge**: If the permissions are locked down, even the all-zero key can't read them

---

## Common Status Codes

### **SW=917E (Length Error)**
- **What it means**: The tag rejected the command because it thinks the length is incorrect
- **Common causes**:
  - Wrong file number (file doesn't exist)
  - Incorrect command format
  - **Most likely**: Permission denied - the authenticated key doesn't have rights to read file settings
- **When you see it**: Usually during file settings read on partially provisioned tags

### **SW=919D (Permission Denied)**
- **What it means**: You're authenticated, but don't have permission for this operation
- **Solution**: Use a different key with higher privileges

### **SW=91AE (Authentication Error)**
- **What it means**: Authentication failed - wrong key
- **Solution**: Check that you're using the correct key file

---

## Security States

### **Factory Default (Insecure)**
```
Slot 0: all-zero key  ⚠️
Slot 1: all-zero key  ⚠️
Slot 2: all-zero key  ⚠️
SDM: Disabled
```
- Anyone can do anything
- Suitable only for testing

### **Partially Provisioned (Your Current State)**
```
Slot 0: all-zero key  ⚠️
Slot 1: provisioned   ✅
Slot 2: all-zero key  ⚠️
SDM: Enabled with slot 1
```
- MAC verification works (can't counterfeit)
- But admin functions still use default key
- Anyone can still change your URL

### **Fully Provisioned (Recommended)**
```
Slot 0: provisioned   ✅
Slot 1: provisioned   ✅
Slot 2: provisioned   ✅
SDM: Enabled with slot 1
```
- All keys are secret and unique
- Only you can modify settings
- Only you can change the URL
- MAC prevents counterfeiting
- Counter prevents replay attacks

---

## Key Files Reference

### **What's in a Key File**
Example: `SDMEncryptionKey.hex`
```
B500E7ECCB9398562E331FE30D51463F
```
- 32 hex characters = 16 bytes = 128 bits
- This is your secret key for AES-128 encryption
- **NEVER** commit these to public repositories!

### **Common Key File Locations**
- `../keys/AppMasterKey.hex` - AppMasterKey (slot 0)
- `../keys/SDMEncryptionKey.hex` - SDM key (slot 1)
- `../keys/FileTwoWrite.hex` - File Two Write key (slot 2)
- `../keys/ntag424_key1_new.hex` - Alternative key (slot TBD)

---

## Troubleshooting Guide

### **"Cannot read file settings (SW=917E)"**
**Cause**: Tag's security policy blocks file settings read with current key
**Solution**:
- Try authenticating with the provisioned config key (slot 0)
- Check if `ntag424_key1_new.hex` is the real slot 0 key
- This is often expected behavior on secured tags

### **"MAC match: X (failed)"**
**Cause**:
- Wrong SDM key
- Tag not properly provisioned
- SDM not enabled
**Solution**: Verify slot 1 key is correct and SDM is configured

### **"No key matched"**
**Cause**: None of your key files work
**Solution**:
- Verify key files exist and have correct format
- Try with all-zero key (factory default)
- Tag might be corrupted or using unknown keys

---

## Glossary

- **AES**: Advanced Encryption Standard - the encryption algorithm used
- **CAR**: Change Access Rights - permission to modify file permissions
- **CC File**: Capability Container - describes tag capabilities
- **CMAC**: Cipher-based Message Authentication Code - the MAC algorithm
- **DESFire**: The underlying chip architecture (NTAG 424 is DESFire-based)
- **EV2**: Evolution 2 - the authentication protocol version
- **MAC**: Message Authentication Code - cryptographic signature
- **NDEF**: NFC Data Exchange Format - standardized data format
- **NFC**: Near Field Communication - the wireless technology
- **PICC**: Proximity Integrated Circuit Card - technical term for the tag
- **SDM**: Secure Dynamic Messaging - the dynamic URL feature
- **UID**: Unique Identifier - the tag's serial number
- **SW**: Status Word - response code from the tag

---

## Best Practices

### **For Production Tags**
1. ✅ Provision ALL three key slots with unique keys
2. ✅ Store key files securely (encrypted, access-controlled)
3. ✅ Enable SDM for anti-counterfeiting
4. ✅ Test MAC verification on your server
5. ✅ Set appropriate access rights (read=free, write=restricted)
6. ✅ Keep backup copies of keys (in secure storage)

### **For Development/Testing**
1. ⚠️ Okay to use all-zero keys initially
2. ⚠️ Test with non-production URLs
3. ⚠️ Clearly label test tags
4. ⚠️ Don't mix test and production keys

### **Never Do This**
1. ❌ Commit key files to public repositories
2. ❌ Use all-zero keys in production
3. ❌ Share keys over insecure channels
4. ❌ Reuse keys across different products
5. ❌ Forget to back up keys (you can't read them back from tags!)

---

## Additional Resources

- **NXP NTAG 424 DNA Datasheet**: Official technical documentation
- **NFC Forum**: NDEF specification standards
- **ISO/IEC 14443**: NFC communication protocol standard

---

*This guide was created to demystify NFC tag security and provisioning concepts.*
