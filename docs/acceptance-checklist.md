# OSC2026 Acceptance Checklist

Checked against the public OSC2026 guidance (updated on 2026-07-13).

| Item | Status | Evidence |
| --- | --- | --- |
| Public repository | Ready | GitHub and GitLink remotes are configured for the same project. |
| MoonBit as primary language | Ready | Library, tests, and demo are MoonBit source files. |
| Clear README | Ready | README explains scope, API, verification, and limits. |
| OSI license | Ready | Full Apache-2.0 license text included in the root. |
| Runnable tests | Ready | `moon test --deny-warn` covers parsing ClientHello, ServerHello, Alerts, Certificates, JA3/JA4/JA4S fingerprinting, streaming, and JSON serialization. |
| Runnable demo | Ready | `moon run cmd/main` executes on native target; cross-compiles to Wasm/JS successfully. |
| CI | Ready | GitHub Actions workflow (`.github/workflows/ci.yml`) is configured for Linux, macOS, and Windows. |
| Source attribution | Ready | `docs/source-attribution.md`. |
| Mooncakes package | Ready | `moon.mod` metadata is ready and published on mooncakes.io. |
| Effective source scale | Tracked | 5,700+ lines of MoonBit implementation plus dedicated tests, exceeding the minimal competition standard. |
