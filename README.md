# MoonTLS-Parser

MoonTLS-Parser is a MoonBit library for passive TLS record inspection, handshake parsing (ClientHello, ServerHello, Certificate, Alert), and fingerprint generation (JA3, JA4-a, JA4S-a). It is designed for traffic-audit probes, sidecar policy filters, and Wasm-based gateways that need routing, auditing, and client-classification signals without decrypting payloads.

This release focuses on the unencrypted TLS handshake surface and features:

- TLS record parsing and length validation.
- Streaming parse of fragmented ClientHello records.
- SNI, ALPN, cipher suite, supported group, EC point format, and signature algorithm extraction from ClientHello.
- GREASE filtering for JA3-compatible fields.
- JA3 canonical string and MD5 digest generation.
- A compact JA4-a style summary for coarse client bucketing.
- **ServerHello Handshake Parsing**: negotiated version (supporting TLS 1.3 supported_versions extensions), cipher suite, random, session ID, and selected ALPN.
- **JA4S-a Fingerprinting**: server handshake fingerprinting for audit classification.
- **Alert Record Parsing**: extract Alert Level and Alert Description with readable string conversion (e.g., handshake_failure, close_notify).
- **Certificate Handshake Parsing**: extract DER certificate lengths in the chain for size auditing.
- **JSON Serialization**: built-in `.to_json()` methods for ClientHello, ServerHello, Alerts, and Certificates.

## Why This Project

The OSC2026 requirement favors reusable MoonBit ecosystem libraries with clear scope, tests, documentation, and maintainable public APIs. TLS record parsing is a good fit because it is useful in security tooling but still small enough to implement as a focused MoonBit package.

This repository is an original MoonBit implementation. It references public TLS, JA3, and JA4 behavior, but it does not copy code from any upstream parser.

## Install

### Option 1: Via Mooncakes Package Manager (Recommended)

Add `moontls-parser` directly to your MoonBit project using `moon add`:

```bash
moon add yhsrtty/moontls-parser
```

Or manually declare the dependency in your `moon.mod`:

```text
import {
  "yhsrtty/moontls-parser@0.1.2",
}
```

Or in JSON format (`moon.mod.json`):

```json
{
  "deps": {
    "yhsrtty/moontls-parser": "0.1.2"
  }
}
```

### Option 2: Local Development & Building from Source

To build, test, and run locally:

```bash
git clone https://github.com/yhsrtty/MoonTLS-Parser.git
cd MoonTLS-Parser
moon check --deny-warn
moon test --deny-warn
moon run cmd/main
```

## Minimal API

### Parsing TLS Records
You can parse any TLS record (Handshake, Alert, etc.) using `parse_tls_record`:

```moonbit
let parsed = parse_tls_record(packet_bytes)
match parsed {
  Ok(ClientHelloRecord(hello)) => {
    println(hello.server_name)
    println(hello.ja3_digest())
    println(hello.to_json())
  }
  Ok(ServerHelloRecord(hello)) => {
    println(hello.selected_alpn)
    println(hello.ja4s_a())
    println(hello.to_json())
  }
  Ok(AlertRecord(alert)) => {
    println(alert.description_string())
  }
  Ok(CertificateRecord(cert)) => {
    println(cert.cert_lengths)
  }
  Ok(GenericRecord(ty, payload)) => {
    println("Other TLS Record")
  }
  Err(err) => println(err)
}
```

For incremental capture pipelines, use `ClientHelloStream`:

```moonbit
let stream = ClientHelloStream::new()
let a = stream.push(first_fragment)
let b = stream.push(second_fragment)
```

`NeedMore` means the record header or record body is incomplete. `Parsed` returns a `ClientHello`. `Rejected` means the buffered bytes are not a valid TLS ClientHello record.

## Current Scope

Implemented:

- TLS record content types `handshake` (0x16) and `alert` (0x15).
- TLS 1.0 through TLS 1.3 record-version range.
- Handshake types `client_hello` (1), `server_hello` (2), and `certificate` (11).
- Extensions `server_name`, `application_layer_protocol_negotiation` (ALPN), `supported_groups`, `ec_point_formats`, `signature_algorithms`, and `supported_versions`.
- Fingerprinting: JA3, JA4-a, and JA4S-a.
- JSON Serialization for parsed elements.

Not implemented yet:

- TCP reassembly beyond a single TLS record.
- Full DER certificate structure parsing (extracts only certificate lengths).
- Encrypted ClientHello decryption.
- Live pcap reading.

Those are natural extension points rather than hidden behavior.

## Verification

The test suite includes hand-built ClientHello, ServerHello, Alert, and Certificate record fixtures.

```bash
moon test --deny-warn
moon check --deny-warn
moon info
```

The repository also includes:

- `.github/workflows/ci.yml` for GitHub CI (Windows, Linux, macOS).
- `scripts/verify_acceptance.ps1` for local OSC2026-style checks.
- `docs/source-attribution.md` for source and licensing notes.
- `docs/acceptance-checklist.md` for the current competition-readiness status.

## License

Apache-2.0. See `LICENSE`.
