# OSC2026 Acceptance Checklist

Checked against the public OSC2026 guidance available on 2026-07-11.

| Item | Status | Evidence |
| --- | --- | --- |
| Public repository | Ready | GitHub and GitLink remotes are configured for the same project. |
| MoonBit as primary language | Ready | Library, tests, and demo are MoonBit source files. |
| Clear README | Ready | README explains scope, API, verification, and limits. |
| OSI license | Ready | Apache-2.0 license included. |
| Runnable tests | Ready | `moon test` covers parser, streaming, JA3, and GREASE filtering. |
| Runnable demo | Ready | `moon run --target js cmd/main`. |
| CI | Ready | GitHub Actions workflow included. |
| Source attribution | Ready | `docs/source-attribution.md`. |
| Mooncakes package | Prepared | `moon.mod` metadata is ready; actual publication depends on account ownership and login. |
| Effective source scale | Tracked | `scripts/verify_acceptance.ps1` counts tracked `.mbt` and `.mbti` lines. |
