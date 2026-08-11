# Changelog

## 0.1.2 - 2026-08-11

- Hardened TLS record and handshake length validation for malformed input.
- Added malformed-packet regression tests covering short and truncated messages.
- Updated acceptance metadata, CI coverage, and the complete Apache-2.0 license.

## 0.1.0 - 2026-07-11

- Added MoonBit project metadata for `yhsrtty/moontls-parser`.
- Added TLS ClientHello parser with record and handshake length validation.
- Added SNI, ALPN, cipher suite, supported group, EC point format, and signature algorithm extraction.
- Added JA3 string and digest generation with GREASE filtering.
- Added streaming parser state for fragmented ClientHello records.
- Added CLI demo, tests, CI, source attribution, and acceptance self-check script.
