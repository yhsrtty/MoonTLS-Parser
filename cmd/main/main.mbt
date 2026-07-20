///|
fn demo_client_hello() -> Bytes {
  Bytes::from_array([
    0x16, 0x03, 0x01, 0x00, 0x79, 0x01, 0x00, 0x00, 0x75, 0x03, 0x03, 0x00, 0x01,
    0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
    0x1c, 0x1d, 0x1e, 0x1f, 0x00, 0x00, 0x08, 0x13, 0x01, 0x13, 0x02, 0xc0, 0x2f,
    0x00, 0xff, 0x01, 0x00, 0x00, 0x44, 0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00,
    0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x6f, 0x72, 0x67,
    0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74,
    0x70, 0x2f, 0x31, 0x2e, 0x31, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d,
    0x00, 0x17, 0x00, 0x18, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x0d, 0x00,
    0x08, 0x00, 0x06, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01,
  ])
}

///|
fn demo_server_hello() -> Bytes {
  Bytes::from_array([
    0x16, 0x03, 0x03, 0x00, 0x3b, 0x02, 0x00, 0x00, 0x37, 0x03, 0x03, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0x00, 0x13, 0x01, 0x00, 0x00, 0x0f, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,
    0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x32,
  ])
}

///|
fn demo_alert() -> Bytes {
  Bytes::from_array([0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28])
}

///|
fn main {
  println("=========================================================")
  println("        MoonTLS-Parser - Advanced Security Audit Engine")
  println("=========================================================")

  println("\n=== 1. Hex Dumps ===")
  let ch = demo_client_hello()
  println("ClientHello Hex:")
  println(@tls.hex_dump(ch[:]))

  println("\n=== 2. Parsing Records ===")
  let parsed_ch = @tls.parse_tls_record(ch).unwrap()
  println(@tls.TlsRecord::dump_tree(parsed_ch))

  let sh = demo_server_hello()
  let parsed_sh = @tls.parse_tls_record(sh).unwrap()
  println(@tls.TlsRecord::dump_tree(parsed_sh))

  let al = demo_alert()
  let parsed_al = @tls.parse_tls_record(al).unwrap()
  println(@tls.TlsRecord::dump_tree(parsed_al))

  println("\n=== 3. Cipher and Extension Formatting ===")
  println(parsed_ch.cipher_summary())
  let exts = parsed_ch.extension_summary()
  let exts_str = exts.join(", ")
  println("Client offered extensions: [\{exts_str}]")

  println(parsed_sh.cipher_summary())
  let sh_exts = parsed_sh.extension_summary()
  let sh_exts_str = sh_exts.join(", ")
  println("Server response extensions: [\{sh_exts_str}]")

  println("\n=== 4. Security Auditing ===")
  match parsed_ch {
    ClientHelloRecord(hello) => {
      let findings = @tls.audit_client_hello_security(hello)
      @tls.print_security_audit_report(findings)
    }
    _ => ()
  }

  println("\n=== 5. Sequence Flow Diagrams ===")
  let records = [parsed_ch, parsed_sh, parsed_al]
  let directions = [true, false, false]
  let text_diag = @tls.visualize_handshake(records, directions)
  println("Sequence Flow Diagram:")
  println(text_diag)

  let mermaid_diag = @tls.generate_mermaid_diagram(records, directions)
  println("Mermaid Diagram Output:")
  println(mermaid_diag)

  println("\n=== 6. Fingerprint Profiling & Database Auditing ===")
  match parsed_ch {
    ClientHelloRecord(hello) => {
      let ja4 = hello.ja4()
      println("Parsed Client JA4 Hash: \{ja4}")
      let info = @tls.lookup_fingerprint_info(ja4)
      println("Database Lookup: \{info}")
    }
    _ => ()
  }

  // Custom lookup examples
  let chrome_fp = "t13d0405_6a170f7f5ea4_c6ca7aae4a09"
  println("Audit Chrome JA4: \{@tls.lookup_fingerprint_info(chrome_fp)}")

  let curl_fp = "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"
  println("Audit curl JA3: \{@tls.lookup_fingerprint_info(curl_fp)}")

  let nginx_fp = "nginx_124_ja4s"
  println("Audit Nginx JA4S: \{@tls.lookup_fingerprint_info(nginx_fp)}")

  println("\n=== 7. Performance Diagnostics ===")
  @tls.run_parser_benchmark(100)
  @tls.run_and_print_performance_audit()
  println("=========================================================")
}
