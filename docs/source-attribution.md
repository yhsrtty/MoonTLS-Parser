# Source Attribution

MoonTLS-Parser is an original MoonBit implementation written for the MoonBit OSC2026 competition track.

## Standards and Public Behavior Referenced

- TLS record and ClientHello structure: public TLS protocol behavior from the TLS specifications.
- JA3: public fingerprint format based on TLS version, cipher suites, extensions, supported groups, EC point formats, and MD5 of the canonical string.
- JA4-a: used here only as a compact coarse summary shape, not as a full JA4 implementation.

## Code Provenance

- Parser, stream state, JA3 formatting, tests, and documentation are implemented in this repository.
- MD5 digest computation uses `moonbitlang/x/crypto`, declared in `moon.mod`.
- No private, closed-source, or commercial code is vendored.
- No third-party parser implementation was copied or translated.

## Competition Work Boundary

The repository was built as a new MoonBit package for passive TLS handshake inspection. Future extensions may add pcap adapters, full JA4 tuple support, ECH-aware classification notes, and richer policy-rule helpers.
