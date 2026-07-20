///|
fn sample_client_hello() -> Bytes {
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
test "parse client hello extracts routing features" {
  let parsed = parse_client_hello(sample_client_hello())
  guard parsed is Ok(hello) else { fail("expected complete ClientHello") }
  debug_inspect(hello.server_name, content="Some(\"example.org\")")
  debug_inspect(hello.alpn_protocols, content="[\"h2\", \"http/1.1\"]")
  debug_inspect(
    hello.cipher_suites.map(fn(x) { uint16_to_hex4(x) }),
    content=(
      #|["1301", "1302", "c02f", "00ff"]
    ),
  )
  debug_inspect(
    hello.supported_groups.map(fn(x) { x.to_string() }),
    content="[\"29\", \"23\", \"24\"]",
  )
}

///|
test "ja3 string and digest are stable" {
  let parsed = parse_client_hello(sample_client_hello())
  guard parsed is Ok(hello) else { fail("expected complete ClientHello") }
  inspect(
    hello.ja3_string(),
    content="771,4865-4866-49199-255,0-16-10-11-13,29-23-24,0",
  )
  inspect(
    hello.ja3_digest(),
    content=(
      #|6a170f7f5ea4eabf4730c665cf5db8a0
    ),
  )
}

///|
test "stream parser waits for full tls record" {
  let data = sample_client_hello()
  let parser = ClientHelloStream::new()
  let first = parser.push(data[:20])
  debug_inspect(first, content="NeedMore")
  let second = parser.push(data[20:])
  guard second is Parsed(hello) else {
    fail("expected parsed after second chunk")
  }
  debug_inspect(hello.server_name, content="Some(\"example.org\")")
}

///|
test "grease values are excluded from ja3" {
  let suites : Array[UInt16] = [0x0a0a, 0x1301, 0x2a2a, 0x1302]
  inspect(normalize_u16_list(suites), content="4865-4866")
}

///|
fn sample_server_hello() -> Bytes {
  Bytes::from_array([
    0x16, 0x03, 0x03, 0x00, 0x3b, 0x02, 0x00, 0x00, 0x37, 0x03, 0x03, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0x00, 0x13, 0x01, 0x00, 0x00, 0x0f, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,
    0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x32,
  ])
}

///|
fn sample_alert() -> Bytes {
  Bytes::from_array([0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28])
}

///|
fn sample_certificate() -> Bytes {
  Bytes::from_array([
    0x16, 0x03, 0x03, 0x00, 0x12, 0x0b, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x0b, 0x00,
    0x00, 0x03, 0x01, 0x02, 0x03, 0x00, 0x00, 0x02, 0x04, 0x05,
  ])
}

///|
test "parse tls record ServerHello" {
  let parsed = parse_tls_record(sample_server_hello())
  guard parsed is Ok(ServerHelloRecord(sh)) else {
    fail("expected ServerHelloRecord")
  }
  inspect(sh.version.to_int(), content="772")
  inspect(sh.cipher_suite.to_int(), content="4865")
  debug_inspect(sh.selected_alpn, content="Some(\"h2\")")
  inspect(sh.ja4s_a(), content="s13a02")
}

///|
test "parse tls record Alert" {
  let parsed = parse_tls_record(sample_alert())
  guard parsed is Ok(AlertRecord(alert)) else { fail("expected AlertRecord") }
  inspect(alert.level_string(), content="fatal")
  inspect(alert.description_string(), content="handshake_failure")
}

///|
test "parse tls record Certificate" {
  let parsed = parse_tls_record(sample_certificate())
  guard parsed is Ok(CertificateRecord(cert)) else {
    fail("expected CertificateRecord")
  }
  debug_inspect(cert.cert_lengths, content="[3, 2]")
}

///|
test "to_json serialization" {
  let sh_parsed = parse_server_hello(sample_server_hello())
  guard sh_parsed is Ok(sh) else { fail("expected ServerHello") }
  inspect(
    sh.to_json(),
    content="{\"version\":772,\"cipher_suite\":4865,\"compression_method\":0,\"extensions\":[43,16],\"selected_alpn\":\"h2\",\"ja4s_a\":\"s13a02\"}",
  )

  let alert_parsed = parse_alert(sample_alert())
  guard alert_parsed is Ok(alert) else { fail("expected Alert") }
  inspect(
    alert.to_json(),
    content="{\"level\":2,\"level_str\":\"fatal\",\"description\":40,\"description_str\":\"handshake_failure\"}",
  )
}

///|
test "sha256 hashing works" {
  let empty = sha256_hex(ascii_bytes(""))
  inspect(
    empty,
    content="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  )

  let hello = sha256_hex(ascii_bytes("hello"))
  inspect(
    hello,
    content="2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
  )
}

///|
test "ja4 client fingerprint matches" {
  let parsed = parse_client_hello(sample_client_hello())
  guard parsed is Ok(hello) else { fail("expected ClientHello") }
  inspect(hello.ja4_a_str(), content="t10d0405h2")
  inspect(hello.ja4_b_str(), content="09ff34cf8194")
  inspect(hello.ja4_c_str(), content="4d18f6442140")
  inspect(hello.ja4(), content="t10d0405h2_09ff34cf8194_4d18f6442140")
}

///|
test "ja4s server fingerprint matches" {
  let parsed = parse_server_hello(sample_server_hello())
  guard parsed is Ok(hello) else { fail("expected ServerHello") }
  inspect(hello.ja4s_a_str(), content="s13sh202")
  inspect(hello.ja4s_b_str(), content="1301")
  inspect(hello.ja4s_c_str(), content="ec9826f46f9c")
  inspect(hello.ja4s(), content="s13sh202_1301_ec9826f46f9c")
}

///|
test "parse ClientKeyExchange record" {
  let record = fixture_client_key_exchange()
  let parsed = parse_tls_record(record)
  guard parsed is Ok(ClientKeyExchangeRecord(cke)) else {
    fail("expected ClientKeyExchangeRecord")
  }
  inspect(cke.raw.length(), content="10")
}

///|
test "parse ServerKeyExchange record" {
  let record = fixture_server_key_exchange()
  let parsed = parse_tls_record(record)
  guard parsed is Ok(ServerKeyExchangeRecord(ske)) else {
    fail("expected ServerKeyExchangeRecord")
  }
  inspect(ske.raw.length(), content="12")
}

///|
test "parse NewSessionTicket record" {
  let record = fixture_new_session_ticket()
  let parsed = parse_tls_record(record)
  guard parsed is Ok(NewSessionTicketRecord(nst)) else {
    fail("expected NewSessionTicketRecord")
  }
  inspect(nst.lifetime.reinterpret_as_int(), content="3600")
  inspect(nst.age_add.reinterpret_as_int(), content="123456")
  inspect(nst.ticket.length(), content="9")
}

///|
test "parse EncryptedExtensions record" {
  let record = fixture_encrypted_extensions()
  let parsed = parse_tls_record(record)
  guard parsed is Ok(EncryptedExtensionsRecord(ee)) else {
    fail("expected EncryptedExtensionsRecord")
  }
  debug_inspect(ee.extensions, content="[0, 16]")
}

///|
test "visualize handshake flow" {
  let records = [
    parse_tls_record(sample_client_hello()).unwrap(),
    parse_tls_record(sample_server_hello()).unwrap(),
    parse_tls_record(fixture_tls_alert_fatal()).unwrap(),
  ]
  let directions = [true, false, false]
  let flow = visualize_handshake(records, directions)

  // Verify flow matches key words
  inspect(flow.contains("ClientHello"), content="true")
  inspect(flow.contains("ServerHello"), content="true")
  inspect(flow.contains("Alert"), content="true")
}

///|
test "fingerprints database lookups" {
  let res_client = lookup_fingerprint_info("t13d0405_6a170f7f5ea4_c6ca7aae4a09")
  inspect(
    res_client,
    content="Client found -> Chrome: Chrome 120+ JA4 Fingerprint",
  )

  let res_server = lookup_fingerprint_info("s13a02_1301_002b0010")
  inspect(
    res_server,
    content="Server found -> Nginx: Nginx TLS 1.3 server hello",
  )

  let res_unknown = lookup_fingerprint_info("non-existent-fingerprint")
  inspect(res_unknown, content="Unknown Fingerprint")

  inspect(client_db_size(), content="27")
  inspect(server_db_size(), content="7")
}

///|
test "benchmark run compiles and executes" {
  run_parser_benchmark(5)
  run_and_print_performance_audit()
}

///|
test "tls extension formatter formats names" {
  inspect(extension_id_to_string(0), content="server_name")
  inspect(
    extension_id_to_string(16),
    content="application_layer_protocol_negotiation (ALPN)",
  )
  inspect(extension_id_to_string(51), content="key_share")
  inspect(extension_id_to_string(65281), content="renegotiation_info")
  inspect(extension_id_to_string(0x1a1a), content="grease_extension (0x1a1a)")
  inspect(extension_id_to_string(999), content="unknown_extension (0x3e7)")
}

///|
test "tls cipher formatter formats names" {
  inspect(cipher_suite_id_to_string(0x1301), content="TLS_AES_128_GCM_SHA256")
  inspect(
    cipher_suite_id_to_string(0xc02f),
    content="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
  )
  inspect(
    cipher_suite_id_to_string(0x000a),
    content="TLS_RSA_WITH_3DES_EDE_CBC_SHA",
  )
  inspect(cipher_suite_id_to_string(0x1a1a), content="grease_cipher (0x1a1a)")
  inspect(cipher_suite_id_to_string(0x9999), content="unknown_cipher (0x9999)")
}

///|
test "tls security auditing evaluates client and server hellos" {
  let parsed_c = parse_client_hello(sample_client_hello())
  guard parsed_c is Ok(hello_c) else { fail("expected ClientHello") }

  let findings_c = audit_client_hello_security(hello_c)
  inspect(findings_c.length(), content="0")

  let parsed_s = parse_server_hello(sample_server_hello())
  guard parsed_s is Ok(hello_s) else { fail("expected ServerHello") }

  let findings_s = audit_server_hello_security(hello_s)
  inspect(findings_s.length(), content="0")
}

///|
test "extended database lookups successfully match signatures" {
  let res_ext_c = lookup_client_fingerprint_ext("chrome_119_ja3")
  inspect(res_ext_c.unwrap(), content="Chrome 119: Chrome 119 on Windows 11")

  let res_ext_s = lookup_server_fingerprint_ext("nginx_124_ja4s")
  inspect(res_ext_s.unwrap(), content="Nginx 1.24: Nginx 1.24 Server Hello")

  let res_ja3 = lookup_ja3_fingerprint("a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0")
  inspect(res_ja3.unwrap(), content="curl 8.x: curl 8.x with OpenSSL 3.x")

  inspect(ja3_db_size(), content="24")
}

///|
test "detailed packet parsing matches correct handshake records" {
  // Test HelloRequest parsing
  let hr_bytes = Bytes::from_array([
    0x16, 0x03, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
  ])
  let parsed_hr = parse_hello_request(hr_bytes[:])
  inspect(parsed_hr is Ok(_), content="true")

  // Test HelloVerifyRequest parsing
  let hvr_bytes = Bytes::from_array([
    0x16, 0x03, 0x03, 0x00, 0x0a, 0x03, 0x00, 0x00, 0x06, 0x03, 0x03, // Version
     0x03, // Cookie len
     0xaa, 0xbb, 0xcc, // Cookie
  ])
  let parsed_hvr = parse_hello_verify_request(hvr_bytes[:])
  inspect(parsed_hvr is Ok(_), content="true")

  // Test CertificateRequest parsing
  let cr_bytes = Bytes::from_array([
    0x16, 0x03, 0x03, 0x00, 0x0b, 0x0d, 0x00, 0x00, 0x07, 0x02, // Types len
     0x01, 0x02, // Types
     0x00, 0x02, // Sig algs len
     0x04, 0x01, // Sig alg
  ])
  let parsed_cr = parse_certificate_request(cr_bytes[:])
  inspect(parsed_cr is Ok(_), content="true")

  // Test CertificateVerify parsing
  let cv_bytes = Bytes::from_array([
    0x16, 0x03, 0x03, 0x00, 0x0b, 0x0f, 0x00, 0x00, 0x07, 0x04, 0x01, // Sig alg
     0x00, 0x03, // Sig len
     0x11, 0x22, 0x33, // Sig
  ])
  let parsed_cv = parse_certificate_verify(cv_bytes[:])
  inspect(parsed_cv is Ok(_), content="true")

  // Test Finished parsing
  let fn_bytes = Bytes::from_array([
    0x16, 0x03, 0x03, 0x00, 0x0b, 0x14, 0x00, 0x00, 0x07, 0x99, 0x88, 0x77, 0x66,
    0x55, 0x44, 0x33, // verify data
  ])
  let parsed_fn = parse_finished(fn_bytes[:])
  inspect(parsed_fn is Ok(_), content="true")
}

///|
test "tls constants and checks" {
  inspect(is_recommended_cipher_id(0x1301), content="true")
  inspect(is_recommended_cipher_id(0xc02f), content="true")
  inspect(is_recommended_cipher_id(0x000a), content="false")

  inspect(is_aead_cipher_id(0x1301), content="true")
  inspect(is_aead_cipher_id(0x000a), content="false")

  inspect(is_tls_version_supported(VERSION_TLS_1_2), content="true")
  inspect(is_tls_version_supported(VERSION_TLS_1_3), content="true")
  inspect(is_tls_version_supported(VERSION_TLS_1_0), content="false")

  inspect(is_tls_13_cipher_id(0x1301), content="true")
  inspect(is_tls_13_cipher_id(0xc02f), content="false")

  inspect(is_weak_cipher_id(0x000a), content="true")
}

///|
test "cipher details database lookup" {
  let details = lookup_cipher_details(0x1301)
  guard details is Some(d) else { fail("expected cipher details") }
  inspect(d.name, content="TLS_AES_128_GCM_SHA256")
  inspect(d.kex, content="ECDHE/DHE")
  inspect(d.enc, content="AES-GCM-128")
  inspect(d.mac, content="AEAD")
  inspect(d.strength, content="128")
  inspect(d.is_recommended, content="true")

  inspect(cipher_details_db_size(), content="68")
}

///|
test "more helper formats" {
  inspect(
    cipher_suite_id_to_string(0x0033),
    content="TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
  )
  inspect(
    cipher_suite_id_to_string(0xcca9),
    content="TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
  )
  inspect(alert_description_to_string((0x00 : Byte)), content="close_notify")
  inspect(alert_description_to_string((0x50 : Byte)), content="internal_error")
  inspect(
    alert_description_to_string((0xff : Byte)),
    content="unknown_alert_description (0xff)",
  )
  inspect(alert_level_to_string((0x01 : Byte)), content="warning")
  inspect(alert_level_to_string((0x02 : Byte)), content="fatal")
  inspect(alert_level_to_string((0xff : Byte)), content="unknown_level")
}
