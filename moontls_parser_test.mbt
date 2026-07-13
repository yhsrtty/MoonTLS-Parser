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
