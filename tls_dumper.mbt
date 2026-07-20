// TLS Record Tree Formatter and Hex-Dumper utility

///|
pub fn TlsRecord::dump_tree(self : TlsRecord) -> String {
  let sb = StringBuilder()
  match self {
    ClientHelloRecord(hello) => {
      sb.write_string("[-] TLS Record: Handshake (ClientHello)\n")
      sb.write_string(
        "  ├─ Legacy Version: \{uint16_to_hex4(hello.legacy_version)} (\{hello.legacy_version.to_int()})\n",
      )
      sb.write_string(
        "  ├─ Record Version: \{uint16_to_hex4(hello.record_version)} (\{hello.record_version.to_int()})\n",
      )
      let sni = hello.server_name.unwrap_or("-")
      sb.write_string("  ├─ SNI (Server Name): \{sni}\n")
      let alpn = hello.alpn_protocols.join(", ")
      sb.write_string("  ├─ ALPN Protocols: [\{alpn}]\n")
      sb.write_string(
        "  ├─ Cipher Suites (count: \{hello.cipher_suites.length()}):\n",
      )
      for c in hello.cipher_suites {
        sb.write_string("  │   ├─ \{uint16_to_hex4(c)}\n")
      }
      sb.write_string(
        "  ├─ Extensions (count: \{hello.extensions.length()}):\n",
      )
      for e in hello.extensions {
        sb.write_string("  │   ├─ \{uint16_to_hex4(e)}\n")
      }
      sb.write_string(
        "  ├─ Supported Groups (count: \{hello.supported_groups.length()}): ",
      )
      let groups_str = hello.supported_groups
        .map(fn(g) { g.to_string() })
        .join(", ")
      sb.write_string("[\{groups_str}]\n")
      sb.write_string(
        "  ├─ JA3 Fingerprint String: \{hello.ja3_string()}\n",
      )
      sb.write_string("  ├─ JA3 Digest (MD5): \{hello.ja3_digest()}\n")
      sb.write_string("  └─ JA4 Fingerprint: \{hello.ja4()}\n")
    }
    ServerHelloRecord(hello) => {
      sb.write_string("[-] TLS Record: Handshake (ServerHello)\n")
      sb.write_string(
        "  ├─ Handshake Version: \{uint16_to_hex4(hello.version)} (\{hello.version.to_int()})\n",
      )
      sb.write_string(
        "  ├─ Cipher Suite: \{uint16_to_hex4(hello.cipher_suite)}\n",
      )
      sb.write_string(
        "  ├─ Compression Method: \{hello.compression_method.to_int()}\n",
      )
      let alpn = hello.selected_alpn.unwrap_or("-")
      sb.write_string("  ├─ Selected ALPN: \{alpn}\n")
      sb.write_string(
        "  ├─ Extensions (count: \{hello.extensions.length()}):\n",
      )
      for e in hello.extensions {
        sb.write_string("  │   ├─ \{uint16_to_hex4(e)}\n")
      }
      sb.write_string("  ├─ JA4S-a Fingerprint Part A: \{hello.ja4s_a()}\n")
      sb.write_string("  └─ JA4S Fingerprint: \{hello.ja4s()}\n")
    }
    AlertRecord(alert) => {
      sb.write_string("[-] TLS Record: Alert\n")
      sb.write_string(
        "  ├─ Level: \{alert.level_string()} (\{alert.level.to_int()})\n",
      )
      sb.write_string(
        "  └─ Description: \{alert.description_string()} (\{alert.description.to_int()})\n",
      )
    }
    CertificateRecord(cert) => {
      sb.write_string("[-] TLS Record: Handshake (Certificate)\n")
      sb.write_string(
        "  └─ Certificate Chains (count: \{cert.cert_lengths.length()}):\n",
      )
      for i in 0..<cert.cert_lengths.length() {
        sb.write_string(
          "      ├─ Certificate [\{i}]: \{cert.cert_lengths[i]} bytes\n",
        )
      }
    }
    ClientKeyExchangeRecord(cke) => {
      sb.write_string("[-] TLS Record: Handshake (ClientKeyExchange)\n")
      sb.write_string(
        "  └─ Key Exchange Payload Length: \{cke.raw.length()} bytes\n",
      )
    }
    ServerKeyExchangeRecord(ske) => {
      sb.write_string("[-] TLS Record: Handshake (ServerKeyExchange)\n")
      sb.write_string(
        "  └─ Key Exchange Payload Length: \{ske.raw.length()} bytes\n",
      )
    }
    NewSessionTicketRecord(nst) => {
      sb.write_string("[-] TLS Record: Handshake (NewSessionTicket)\n")
      sb.write_string(
        "  ├─ Ticket Lifetime: \{nst.lifetime.reinterpret_as_int()} seconds\n",
      )
      sb.write_string(
        "  ├─ Ticket Age Add: \{nst.age_add.reinterpret_as_int()}\n",
      )
      sb.write_string("  └─ Ticket Length: \{nst.ticket.length()} bytes\n")
    }
    EncryptedExtensionsRecord(ee) => {
      sb.write_string("[-] TLS Record: Handshake (EncryptedExtensions)\n")
      sb.write_string(
        "  └─ Extensions (count: \{ee.extensions.length()}):\n",
      )
      for e in ee.extensions {
        sb.write_string("      ├─ \{uint16_to_hex4(e)}\n")
      }
    }
    HelloRequestRecord(_) => {
      sb.write_string("[-] TLS Record: Handshake (HelloRequest)\n")
      sb.write_string("  └─ Body: Empty\n")
    }
    HelloVerifyRequestRecord(hvr) => {
      sb.write_string("[-] TLS Record: Handshake (HelloVerifyRequest)\n")
      sb.write_string(
        "  ├─ Handshake Version: \{uint16_to_hex4(hvr.version)} (\{hvr.version.to_int()})\n",
      )
      sb.write_string("  └─ Cookie Length: \{hvr.cookie.length()} bytes\n")
    }
    CertificateRequestRecord(cr) => {
      sb.write_string("[-] TLS Record: Handshake (CertificateRequest)\n")
      let types_str = cr.certificate_types
        .map(fn(t) { t.to_int().to_string() })
        .join(", ")
      sb.write_string("  ├─ Cert Types: [\{types_str}]\n")
      let algs_str = cr.supported_signature_algorithms
        .map(fn(a) { uint16_to_hex4(a) })
        .join(", ")
      sb.write_string("  └─ Sig Algs: [\{algs_str}]\n")
    }
    CertificateVerifyRecord(cv) => {
      sb.write_string("[-] TLS Record: Handshake (CertificateVerify)\n")
      sb.write_string(
        "  ├─ Sig Alg: \{uint16_to_hex4(cv.signature_algorithm)}\n",
      )
      sb.write_string(
        "  └─ Signature Length: \{cv.signature.length()} bytes\n",
      )
    }
    FinishedRecord(fn_) => {
      sb.write_string("[-] TLS Record: Handshake (Finished)\n")
      sb.write_string(
        "  └─ Verify Data Length: \{fn_.verify_data.length()} bytes\n",
      )
    }
    GenericRecord(ty, payload) => {
      let ty_str = match ty {
        ChangeCipherSpec => "ChangeCipherSpec"
        Handshake => "Handshake (Generic)"
        ApplicationData => "ApplicationData"
        Unknown(b) => "Unknown (0x\{b.to_int().to_string(radix=16)})"
      }
      sb.write_string("[-] TLS Record: \{ty_str}\n")
      sb.write_string("  └─ Payload Length: \{payload.length()} bytes\n")
    }
  }
  sb.to_string()
}

///|
pub fn hex_dump(data : BytesView) -> String {
  let sb = StringBuilder()
  let len = data.length()
  let mut offset = 0
  while offset < len {
    // Print offset
    let off_str = offset.to_string(radix=16).pad_start(4, '0')
    sb.write_string(off_str)
    sb.write_string("  ")

    // Print hex values
    let mut i = 0
    while i < 16 {
      if offset + i < len {
        let b = data[offset + i]
        let hex = b.to_int().to_string(radix=16).pad_start(2, '0')
        sb.write_string(hex)
        sb.write_string(" ")
      } else {
        sb.write_string("   ")
      }
      if i == 7 {
        sb.write_string(" ")
      }
      i = i + 1
    }

    sb.write_string(" |")
    // Print ASCII representation
    i = 0
    while i < 16 {
      if offset + i < len {
        let b = data[offset + i].to_int()
        if b >= 32 && b <= 126 {
          match b.to_char() {
            Some(c) => sb.write_char(c)
            None => sb.write_string(".")
          }
        } else {
          sb.write_string(".")
        }
      }
      i = i + 1
    }
    sb.write_string("|\n")
    offset = offset + 16
  }
  sb.to_string()
}
