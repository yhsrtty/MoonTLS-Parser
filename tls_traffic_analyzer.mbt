// Security audit and vulnerability analyzer for TLS configurations

///|
pub struct SecurityFinding {
  severity : String // "info", "warning", "critical"
  category : String
  finding : String
  suggestion : String
} derive(Debug, Eq)

///|
pub fn audit_client_hello_security(
  hello : ClientHello,
) -> Array[SecurityFinding] {
  let findings = []

  // 1. Version Audit
  let ver = hello.legacy_version.to_int()
  if ver < 0x0303 {
    findings.push({
      severity: "critical",
      category: "Protocol Version",
      finding: "Legacy TLS version offered: 0x" + ver.to_string(radix=16),
      suggestion: "Disable TLS 1.0 (0x0301) and TLS 1.1 (0x0302). Force TLS 1.2 minimum version.",
    })
  }

  // 2. Cipher Suite Audit
  let mut has_null = false
  let mut has_rc4 = false
  let mut has_3des = false
  let mut has_weak_export = false

  for cipher in hello.cipher_suites {
    let c_val = cipher.to_int()
    // Null Ciphers: 0x0001 (NULL_MD5), 0x0002 (NULL_SHA), 0x002c (NULL_SHA256)
    if c_val == 0x0001 || c_val == 0x0002 || c_val == 0x002c {
      has_null = true
    }
    // RC4 Ciphers: e.g. 0x0004, 0x0005
    if c_val == 0x0004 || c_val == 0x0005 {
      has_rc4 = true
    }
    // 3DES Ciphers: e.g. 0x000a
    if c_val == 0x000a {
      has_3des = true
    }
    // Weak Export Ciphers: e.g. 0x0003, 0x0006, 0x0008, 0x0011, 0x0014
    if c_val == 0x0003 ||
      c_val == 0x0006 ||
      c_val == 0x0008 ||
      c_val == 0x0011 ||
      c_val == 0x0014 {
      has_weak_export = true
    }
  }

  if has_null {
    findings.push({
      severity: "critical",
      category: "Cryptography",
      finding: "Client offers NULL encryption cipher suites (no confidentiality)",
      suggestion: "Immediately remove NULL cipher suites from active configurations.",
    })
  }
  if has_rc4 {
    findings.push({
      severity: "critical",
      category: "Cryptography",
      finding: "Client offers RC4 cipher suites (known cryptographic weaknesses)",
      suggestion: "Disable RC4 cipher suites. Replace with AES-GCM or ChaCha20-Poly1305.",
    })
  }
  if has_3des {
    findings.push({
      severity: "warning",
      category: "Cryptography",
      finding: "Client offers 3DES/DES cipher suites (SWEET32 vulnerability hazard)",
      suggestion: "Disable Triple-DES (3DES) suites. Enforce AES-GCM block ciphers.",
    })
  }
  if has_weak_export {
    findings.push({
      severity: "critical",
      category: "Cryptography",
      finding: "Client offers legacy export-grade cipher suites (susceptible to FREAK/Logjam)",
      suggestion: "Disable all export-grade ciphers (usually marked EXPORT).",
    })
  }

  // 3. SNI Audit
  if hello.server_name is None {
    findings.push({
      severity: "info",
      category: "Privacy",
      finding: "ClientHello lacks Server Name Indication (SNI) extension",
      suggestion: "Enable SNI to allow proper routing on multi-tenant virtual hosting servers.",
    })
  }

  // 4. ALPN Audit
  if hello.alpn_protocols.length() == 0 {
    findings.push({
      severity: "info",
      category: "Performance",
      finding: "No Application-Layer Protocol Negotiation (ALPN) extensions present",
      suggestion: "Enable ALPN to negotiate HTTP/2 or HTTP/3 without extra roundtrips.",
    })
  }

  findings
}

///|
pub fn audit_server_hello_security(
  hello : ServerHello,
) -> Array[SecurityFinding] {
  let findings = []

  // 1. Version Audit
  let ver = hello.version.to_int()
  if ver < 0x0303 {
    findings.push({
      severity: "critical",
      category: "Protocol Version",
      finding: "Server negotiated deprecated legacy version: 0x" +
      ver.to_string(radix=16),
      suggestion: "Upgrade server configuration to negotiate TLS 1.2 or TLS 1.3 only.",
    })
  }

  // 2. Cipher Suite Audit
  let cipher = hello.cipher_suite.to_int()
  // Check for weak ciphers
  if cipher == 0x000a {
    findings.push({
      severity: "critical",
      category: "Cryptography",
      finding: "Server selected weak 3DES cipher suite: TLS_RSA_WITH_3DES_EDE_CBC_SHA",
      suggestion: "Remove 3DES/DES cipher suites from server settings.",
    })
  } else if cipher == 0x0001 || cipher == 0x0002 || cipher == 0x002c {
    findings.push({
      severity: "critical",
      category: "Cryptography",
      finding: "Server selected NULL encryption cipher suite (plaintext traffic!)",
      suggestion: "Disable NULL cipher suites. Plaintext traffic leaks all credentials.",
    })
  }

  findings
}

///|
pub fn print_security_audit_report(findings : Array[SecurityFinding]) -> Unit {
  if findings.length() == 0 {
    println("[+] TLS Security Audit: Clean. No issues found.")
    return
  }
  println("=================================================================")
  println("                 TLS CONFIGURATION SECURITY AUDIT REPORT")
  println("=================================================================")
  for f in findings {
    let sev = f.severity.to_upper()
    println("[\{sev}] Category: \{f.category}")
    println("  └─ Issue: \{f.finding}")
    println("  └─ Suggestion: \{f.suggestion}\n")
  }
  println("=================================================================")
}
