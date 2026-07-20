// Comprehensive Security & Malformed Packet Safety Test Suite

///|
/// Test truncated TLS record headers (0 to 4 bytes)
test "security audit: truncated record headers return IncompleteRecord without panic" {
  let empty = Bytes::from_array([])
  inspect(
    parse_tls_record(empty[:]) is Err(IncompleteRecord(_)),
    content="true",
  )

  let b1 = Bytes::from_array([(0x16 : Byte)])
  inspect(parse_tls_record(b1[:]) is Err(IncompleteRecord(_)), content="true")

  let b2 = Bytes::from_array([(0x16 : Byte), (0x03 : Byte)])
  inspect(parse_tls_record(b2[:]) is Err(IncompleteRecord(_)), content="true")

  let b3 = Bytes::from_array([(0x16 : Byte), (0x03 : Byte), (0x03 : Byte)])
  inspect(parse_tls_record(b3[:]) is Err(IncompleteRecord(_)), content="true")

  let b4 = Bytes::from_array([
    (0x16 : Byte),
    (0x03 : Byte),
    (0x03 : Byte),
    (0x00 : Byte),
  ])
  inspect(parse_tls_record(b4[:]) is Err(IncompleteRecord(_)), content="true")
}

///|
/// Test unknown / unhandled TLS record content types
test "security audit: unknown content types parsed safely as GenericRecord" {
  // Content type 0x99 (unknown), version 3.3, len 2, data 0xaa 0xbb
  let raw = Bytes::from_array([
    (0x99 : Byte),
    (0x03 : Byte),
    (0x03 : Byte),
    (0x00 : Byte),
    (0x02 : Byte),
    (0xaa : Byte),
    (0xbb : Byte),
  ])
  match parse_tls_record(raw[:]) {
    Ok(GenericRecord(Unknown(b), _)) => inspect(b.to_int(), content="153")
    _ => fail("expected GenericRecord Unknown")
  }
}

///|
/// Test over-declared record lengths (record header claims 65535 bytes but only 5 bytes present)
test "security audit: over-declared record length returns IncompleteRecord" {
  let raw = Bytes::from_array([
    (0x16 : Byte),
    (0x03 : Byte),
    (0x03 : Byte),
    (0xff : Byte),
    (0xff : Byte),
    (0x01 : Byte),
    (0x00 : Byte),
    (0x00 : Byte),
    (0x05 : Byte),
    (0x00 : Byte),
  ])
  inspect(parse_tls_record(raw[:]) is Err(IncompleteRecord(_)), content="true")
}

///|
/// Test unsupported record versions for ClientHello
test "security audit: unsupported record version returns UnsupportedRecordVersion" {
  // SSL 3.0 (0x0300) ClientHello
  let raw = Bytes::from_array([
    (0x16 : Byte),
    (0x03 : Byte),
    (0x00 : Byte),
    (0x00 : Byte),
    (0x05 : Byte),
    (0x01 : Byte),
    (0x00 : Byte),
    (0x00 : Byte),
    (0x01 : Byte),
    (0x00 : Byte),
  ])
  inspect(
    parse_client_hello(raw[:]) is Err(UnsupportedRecordVersion(_)),
    content="true",
  )
}

///|
/// Test unknown / unsupported Handshake types
test "security audit: unknown handshake types returned safely as GenericRecord" {
  // Handshake Type 0x64 (100), record len 5, handshake len 1
  let raw = Bytes::from_array([
    (0x16 : Byte),
    (0x03 : Byte),
    (0x03 : Byte),
    (0x00 : Byte),
    (0x05 : Byte),
    (0x64 : Byte),
    (0x00 : Byte),
    (0x00 : Byte),
    (0x01 : Byte),
    (0xff : Byte),
  ])
  match parse_tls_record(raw[:]) {
    Ok(GenericRecord(Handshake, _)) => ()
    _ => fail("expected GenericRecord Handshake")
  }
}

///|
/// Test malformed ClientHello with truncated fixed header (< 34 bytes)
test "security audit: ClientHello with truncated fixed header returns BadLength" {
  // Handshake Type 1 (ClientHello), record len 10, handshake len 6 (short)
  let raw = Bytes::from_array([
    (0x16 : Byte),
    (0x03 : Byte),
    (0x03 : Byte),
    (0x00 : Byte),
    (0x0a : Byte),
    (0x01 : Byte),
    (0x00 : Byte),
    (0x00 : Byte),
    (0x06 : Byte),
    (0x03 : Byte),
    (0x03 : Byte),
    (0x11 : Byte),
    (0x22 : Byte),
    (0x33 : Byte),
    (0x44 : Byte),
  ])
  inspect(parse_client_hello(raw[:]) is Err(BadLength(_)), content="true")
}

///|
/// Test malformed ClientHello with invalid session ID length
test "security audit: ClientHello with invalid session ID length returns BadLength" {
  // Fixed header present (34 bytes), session ID length declared as 200 (exceeds handshake body)
  let arr : Array[Byte] = [
    (0x16 : Byte),
    (0x03 : Byte),
    (0x03 : Byte),
    (0x00 : Byte),
    (0x2d : Byte),
    (0x01 : Byte),
    (0x00 : Byte),
    (0x00 : Byte),
    (0x29 : Byte),
    (0x03 : Byte),
    (0x03 : Byte),
  ]
  // Push 32 random bytes
  for i in 0..<32 {
    arr.push(i.to_byte())
  }
  // Session ID length 200
  arr.push((0xc8 : Byte))
  // Push 6 extra bytes to fulfill record length 45 (50 total bytes)
  for _i in 0..<6 {
    arr.push((0x00 : Byte))
  }

  let raw = Bytes::from_array(arr)
  inspect(parse_client_hello(raw[:]) is Err(BadLength(_)), content="true")
}

///|
/// Test malformed ClientHello with odd cipher suite length
test "security audit: ClientHello with odd cipher suite length returns BadLength" {
  let arr : Array[Byte] = [
    (0x16 : Byte),
    (0x03 : Byte),
    (0x03 : Byte),
    (0x00 : Byte),
    (0x30 : Byte),
    (0x01 : Byte),
    (0x00 : Byte),
    (0x00 : Byte),
    (0x2c : Byte),
    (0x03 : Byte),
    (0x03 : Byte),
  ]
  for i in 0..<32 {
    arr.push(i.to_byte())
  }
  arr.push((0x00 : Byte)) // Session ID len 0
  arr.push((0x00 : Byte)) // Cipher suites len MSB
  arr.push((0x03 : Byte)) // Cipher suites len LSB (3 - odd, invalid!)
  arr.push((0x13 : Byte))
  arr.push((0x01 : Byte))
  arr.push((0x13 : Byte))
  // Push 4 extra bytes to fulfill record length 48 (53 total bytes)
  for _i in 0..<4 {
    arr.push((0x00 : Byte))
  }

  let raw = Bytes::from_array(arr)
  inspect(parse_client_hello(raw[:]) is Err(BadLength(_)), content="true")
}

///|
/// Test malformed ServerHello with invalid session ID length
test "security audit: ServerHello with invalid session ID length returns BadLength" {
  let arr : Array[Byte] = [
    (0x16 : Byte),
    (0x03 : Byte),
    (0x03 : Byte),
    (0x00 : Byte),
    (0x2d : Byte),
    (0x02 : Byte),
    (0x00 : Byte),
    (0x00 : Byte),
    (0x29 : Byte),
    (0x03 : Byte),
    (0x03 : Byte),
  ]
  for i in 0..<32 {
    arr.push(i.to_byte())
  }
  arr.push((0xc8 : Byte)) // Session ID len 200 (invalid)
  // Push 6 extra bytes to fulfill record length 45 (50 total bytes)
  for _i in 0..<6 {
    arr.push((0x00 : Byte))
  }

  let raw = Bytes::from_array(arr)
  inspect(parse_server_hello(raw[:]) is Err(BadLength(_)), content="true")
}

///|
/// Test Alert record with invalid length != 2
test "security audit: Alert with invalid payload length returns InvalidAlertLength" {
  // Alert record declared with length 3 (invalid, must be 2)
  let raw = Bytes::from_array([
    (0x15 : Byte),
    (0x03 : Byte),
    (0x03 : Byte),
    (0x00 : Byte),
    (0x03 : Byte),
    (0x02 : Byte),
    (0x28 : Byte),
    (0x00 : Byte),
  ])
  inspect(parse_alert(raw[:]) is Err(InvalidAlertLength), content="true")

  // Alert record declared with length 1
  let raw2 = Bytes::from_array([
    (0x15 : Byte),
    (0x03 : Byte),
    (0x03 : Byte),
    (0x00 : Byte),
    (0x01 : Byte),
    (0x02 : Byte),
  ])
  inspect(parse_alert(raw2[:]) is Err(InvalidAlertLength), content="true")
}

///|
/// Test Certificate record with oversized certs list length
test "security audit: Certificate record with oversized certs list returns BadLength" {
  // Handshake Type 11, record len 8, handshake len 4, certs list len declared 1000
  let raw = Bytes::from_array([
    (0x16 : Byte),
    (0x03 : Byte),
    (0x03 : Byte),
    (0x00 : Byte),
    (0x08 : Byte),
    (0x0b : Byte),
    (0x00 : Byte),
    (0x00 : Byte),
    (0x04 : Byte),
    (0x00 : Byte),
    (0x03 : Byte),
    (0xe8 : Byte),
    (0x00 : Byte),
  ])
  inspect(parse_certificate(raw[:]) is Err(BadLength(_)), content="true")
}

///|
/// Test Handshake parsers with wrong record type (e.g. non-0x16)
test "security audit: KeyExchange parsers with non-handshake record type return NotTlsHandshake" {
  // Content type 0x17 (ApplicationData), but sent to parse_client_key_exchange
  let raw = Bytes::from_array([
    (0x17 : Byte),
    (0x03 : Byte),
    (0x03 : Byte),
    (0x00 : Byte),
    (0x05 : Byte),
    (0x10 : Byte),
    (0x00 : Byte),
    (0x00 : Byte),
    (0x01 : Byte),
    (0x00 : Byte),
  ])
  inspect(
    parse_client_key_exchange(raw[:]) is Err(NotTlsHandshake),
    content="true",
  )
  inspect(
    parse_server_key_exchange(raw[:]) is Err(NotTlsHandshake),
    content="true",
  )
  inspect(
    parse_new_session_ticket(raw[:]) is Err(NotTlsHandshake),
    content="true",
  )
  inspect(
    parse_encrypted_extensions(raw[:]) is Err(NotTlsHandshake),
    content="true",
  )
  inspect(parse_hello_request(raw[:]) is Err(NotTlsHandshake), content="true")
  inspect(
    parse_hello_verify_request(raw[:]) is Err(NotTlsHandshake),
    content="true",
  )
  inspect(
    parse_certificate_request(raw[:]) is Err(NotTlsHandshake),
    content="true",
  )
  inspect(
    parse_certificate_verify(raw[:]) is Err(NotTlsHandshake),
    content="true",
  )
  inspect(parse_finished(raw[:]) is Err(NotTlsHandshake), content="true")
}

///|
/// Test Fuzzing: Feed 100 randomized byte arrays to all parsers without panicking
test "security audit: fuzz testing guarantees zero panics/aborts on arbitrary bytes" {
  let mut seed = 0x12345678
  for len in 1..<50 {
    for _iter in 0..<2 {
      let buf = Array::new(capacity=len)
      for _i in 0..<len {
        seed = (seed * 1103515245 + 12345) & 0x7fffffff
        buf.push(((seed >> 16) & 0xff).to_byte())
      }
      let raw = Bytes::from_array(buf)

      let _ = parse_tls_record(raw[:])
      let _ = parse_client_hello(raw[:])
      let _ = parse_server_hello(raw[:])
      let _ = parse_alert(raw[:])
      let _ = parse_certificate(raw[:])
      let _ = parse_client_key_exchange(raw[:])
      let _ = parse_server_key_exchange(raw[:])
      let _ = parse_new_session_ticket(raw[:])
      let _ = parse_encrypted_extensions(raw[:])
      let _ = parse_hello_request(raw[:])
      let _ = parse_hello_verify_request(raw[:])
      let _ = parse_certificate_request(raw[:])
      let _ = parse_certificate_verify(raw[:])
      let _ = parse_finished(raw[:])
      let _ = parse_key_share_client(raw[:])
      let _ = parse_key_share_server(raw[:])
      let _ = parse_supported_versions_client(raw[:])
      let _ = parse_server_name_list(raw[:])
      let _ = parse_tls_cookie(raw[:])
    }
  }
}
