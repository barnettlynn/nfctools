# NTAG 424 DNA Features and Uses

Below is a concise, feature‑by‑feature list for **NTAG 424 DNA** and what each feature is typically used for.

## Features and Uses

- **NFC Forum Type 4 Tag; ISO/IEC 14443A‑2/‑3/‑4 and ISO/IEC 7816‑4 command frames** — broad interoperability with phones and standard readers for “tap to read” and “tap to transact” use cases.
- **Fast data rates (106/212/424/848 kbit/s), frame size up to 128 bytes, operating distance up to ~10 cm** — faster, more reliable user taps and better UX with modern phones.
- **416 bytes user memory in an ISO 7816‑4 file system (32‑byte CC file, 256‑byte NDEF file, 128‑byte protected data file)** — store a standard NDEF URL plus sensitive data in a separate protected file.
- **Per‑file access rights (R/W/RW/Config) and configurable communication modes (plain, MACed, fully encrypted)** — granular security policy per file and per operation.
- **AES‑128 cryptography with five customer‑defined keys + 3‑pass mutual authentication** — secure reader/host authentication and protected data access.
- **Secure Dynamic Messaging (SDM) / Secure Unique NFC (SUN)** — generates a tap‑unique, integrity‑protected dynamic NDEF message (ASCII mirrored into the NDEF), enabling secure URL‑based authentication without a dedicated app.
- **Incremental NFC counter** — count taps for analytics, anti‑replay, or access‑limit use cases; it can be mirrored in SDM/SUN output.
- **Optional Random ID and encrypted UID/data mirroring** — privacy protection and reduced UID tracking risk.
- **ECC‑based NXP originality signature + AES‑based originality check** — verify genuine tags and detect clones.
- **Leakage‑Resilient Primitive (LRP) wrapped AES and Common Criteria EAL4 certification** — improved resistance to side‑channel attacks and independent security assurance.
- **Anti‑tearing, 50‑year data retention, 200k write endurance** — robust data integrity for long‑lived products.
- **High input capacitance (50 pF)** — supports smaller antennas and compact tag designs.

## TagTamper Variant (only if you have NTAG 424 DNA TagTamper)

- **Tamper loop** — indicates if a seal was opened and can be reflected to the reader without a dedicated app.
