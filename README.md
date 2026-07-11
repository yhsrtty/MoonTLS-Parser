# MoonTLS-Parser

MoonTLS-Parser is a MoonBit library for passive TLS ClientHello inspection and JA3 fingerprint generation. It is designed for traffic-audit probes, sidecar policy filters, and Wasm-based gateways that need routing and client-classification signals without decrypting payloads.

The first release focuses on the unencrypted TLS handshake surface:

- TLS record and ClientHello length validation.
- Streaming parse of fragmented ClientHello records.
- SNI, ALPN, cipher suite, supported group, EC point format, and signature algorithm extraction.
- GREASE filtering for JA3-compatible fields.
- JA3 canonical string and MD5 digest generation.
- A compact JA4-a style summary for coarse client bucketing.

MD5 is used only because JA3 identifies clients with an MD5 digest of the canonical fingerprint string. It is not used here as a security primitive.

## Why This Project

The OSC2026 requirement favors reusable MoonBit ecosystem libraries with clear scope, tests, documentation, and maintainable public APIs. TLS ClientHello parsing is a good fit because it is useful in security tooling but still small enough to implement as a focused MoonBit package.

This repository is an original MoonBit implementation. It references public TLS and JA3 behavior, but it does not copy code from an upstream parser.

## Install

After the package is published on Mooncakes:

```bash
moon add yhsrtty/moontls-parser
```

For local development:

```bash
moon check
moon test
moon run --target js cmd/main
```

## Minimal API

```moonbit
let parsed = parse_client_hello(packet_bytes)
match parsed {
  Ok(hello) => {
    println(hello.server_name)
    println(hello.alpn_protocols)
    println(hello.ja3_string())
    println(hello.ja3_digest())
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

- TLS record content type `handshake`.
- TLS 1.0 through TLS 1.3 record-version range.
- Handshake type `client_hello`.
- Extensions `server_name`, `application_layer_protocol_negotiation`, `supported_groups`, `ec_point_formats`, and `signature_algorithms`.
- JA3 canonical fields: version, cipher suites, extensions, supported groups, and EC point formats.

Not implemented yet:

- TCP reassembly beyond a single TLS record.
- Certificate parsing.
- Encrypted ClientHello decryption.
- Full JA4 transport tuple generation.
- Live pcap reading.

Those are natural extension points rather than hidden behavior.

## Verification

The test suite includes a hand-built ClientHello fixture with SNI `example.org`, ALPN `h2` and `http/1.1`, TLS 1.3 ciphers, supported groups, and signature algorithms.

```bash
moon test
moon check --warn-list +73
moon info
```

The repository also includes:

- `.github/workflows/ci.yml` for GitHub CI.
- `scripts/verify_acceptance.ps1` for local OSC2026-style checks.
- `docs/source-attribution.md` for source and licensing notes.
- `docs/acceptance-checklist.md` for the current competition-readiness status.

## License

Apache-2.0. See `LICENSE`.
