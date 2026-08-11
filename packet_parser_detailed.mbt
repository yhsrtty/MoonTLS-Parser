// Parsing implementations for HelloRequest, HelloVerifyRequest, CertificateRequest, CertificateVerify, and Finished

///|

///|
pub fn parse_hello_request(
  data : BytesView,
) -> Result[HelloRequest, ParseError] {
  if data.length() < 5 {
    return Err(IncompleteRecord(expected=5, available=data.length()))
  }
  if data[0].to_int() != 0x16 {
    return Err(NotTlsHandshake)
  }
  guard read_u16_int(data, 3) is Some(record_len) else {
    return Err(BadLength(field="record.length", offset=3))
  }
  if record_len < 4 {
    return Err(BadLength(field="handshake.header", offset=5))
  }
  let record_end = 5 + record_len
  if record_end < 5 || data.length() < record_end {
    return Err(IncompleteRecord(expected=record_end, available=data.length()))
  }
  if data[5].to_int() != 0 {
    return Err(BadHandshakeType(data[5].to_int()))
  }
  guard read_u24_int(data, 6) is Some(handshake_len) else {
    return Err(BadLength(field="handshake.length", offset=6))
  }
  let body_end = 9 + handshake_len
  if handshake_len != 0 || body_end > record_end {
    return Err(BadLength(field="hello_request.body", offset=9))
  }
  Ok({ dummy: 0 })
}

///|
pub fn parse_hello_verify_request(
  data : BytesView,
) -> Result[HelloVerifyRequest, ParseError] {
  if data.length() < 5 {
    return Err(IncompleteRecord(expected=5, available=data.length()))
  }
  if data[0].to_int() != 0x16 {
    return Err(NotTlsHandshake)
  }
  guard read_u16_int(data, 3) is Some(record_len) else {
    return Err(BadLength(field="record.length", offset=3))
  }
  if record_len < 4 {
    return Err(BadLength(field="handshake.header", offset=5))
  }
  let record_end = 5 + record_len
  if record_end < 5 || data.length() < record_end {
    return Err(IncompleteRecord(expected=record_end, available=data.length()))
  }
  if data[5].to_int() != 3 {
    return Err(BadHandshakeType(data[5].to_int()))
  }
  guard read_u24_int(data, 6) is Some(handshake_len) else {
    return Err(BadLength(field="handshake.length", offset=6))
  }
  let body_offset = 9
  if handshake_len < 0 || body_offset + handshake_len > record_end {
    return Err(BadLength(field="handshake.body", offset=body_offset))
  }

  // HelloVerifyRequest: Version (2 bytes) + Cookie Length (1 byte) + Cookie
  if handshake_len < 3 {
    return Err(BadLength(field="hello_verify.header", offset=body_offset))
  }

  guard read_u16(data, body_offset) is Some(version) else {
    return Err(BadLength(field="hello_verify.version", offset=body_offset))
  }

  let cookie_len = data[body_offset + 2].to_int()
  if cookie_len < 0 ||
    body_offset + 3 + cookie_len > body_offset + handshake_len ||
    !has_range(data, body_offset + 3, cookie_len) {
    return Err(BadLength(field="hello_verify.cookie", offset=body_offset + 3))
  }

  let cookie_arr = Array::new(capacity=cookie_len)
  for i in 0..<cookie_len {
    cookie_arr.push(data[body_offset + 3 + i])
  }
  let cookie = Bytes::from_array(cookie_arr)

  Ok({ version, cookie })
}

///|
pub fn parse_certificate_request(
  data : BytesView,
) -> Result[CertificateRequest, ParseError] {
  if data.length() < 5 {
    return Err(IncompleteRecord(expected=5, available=data.length()))
  }
  if data[0].to_int() != 0x16 {
    return Err(NotTlsHandshake)
  }
  guard read_u16_int(data, 3) is Some(record_len) else {
    return Err(BadLength(field="record.length", offset=3))
  }
  if record_len < 4 {
    return Err(BadLength(field="handshake.header", offset=5))
  }
  let record_end = 5 + record_len
  if record_end < 5 || data.length() < record_end {
    return Err(IncompleteRecord(expected=record_end, available=data.length()))
  }
  if data[5].to_int() != 13 {
    return Err(BadHandshakeType(data[5].to_int()))
  }
  guard read_u24_int(data, 6) is Some(handshake_len) else {
    return Err(BadLength(field="handshake.length", offset=6))
  }
  let body_offset = 9
  let body_end = body_offset + handshake_len
  if handshake_len < 0 || body_end < body_offset || body_end > record_end {
    return Err(BadLength(field="handshake.body", offset=body_offset))
  }

  // CertificateRequest:
  // Certificate Types Length (1 byte) + Types +
  // [TLS 1.2] Supported Signature Algorithms Length (2 bytes) + Algorithms
  if handshake_len < 1 {
    return Err(BadLength(field="cert_request.header", offset=body_offset))
  }

  let types_len = data[body_offset].to_int()
  if types_len < 0 ||
    body_offset + 1 + types_len > body_end ||
    !has_range(data, body_offset + 1, types_len) {
    return Err(BadLength(field="cert_request.types", offset=body_offset + 1))
  }

  let certificate_types = Array::new(capacity=types_len)
  for i in 0..<types_len {
    certificate_types.push(data[body_offset + 1 + i])
  }

  let mut cursor = body_offset + 1 + types_len
  let sig_algs : Array[UInt16] = []

  if cursor + 2 <= body_end {
    guard read_u16_int(data, cursor) is Some(sig_algs_len) else {
      return Err(BadLength(field="cert_request.sig_algs_len", offset=cursor))
    }
    cursor = cursor + 2
    if sig_algs_len < 0 || cursor + sig_algs_len > body_end {
      return Err(BadLength(field="cert_request.sig_algs_body", offset=cursor))
    }
    let end_sig = cursor + sig_algs_len
    while cursor + 2 <= end_sig {
      guard read_u16(data, cursor) is Some(alg) else {
        return Err(BadLength(field="cert_request.alg", offset=cursor))
      }
      sig_algs.push(alg)
      cursor = cursor + 2
    }
    if cursor != end_sig {
      return Err(BadLength(field="cert_request.sig_algs_trailing", offset=cursor))
    }
  }

  if cursor != body_end {
    return Err(BadLength(field="cert_request.trailing", offset=cursor))
  }

  Ok({ certificate_types, supported_signature_algorithms: sig_algs })
}

///|
pub fn parse_certificate_verify(
  data : BytesView,
) -> Result[CertificateVerify, ParseError] {
  if data.length() < 5 {
    return Err(IncompleteRecord(expected=5, available=data.length()))
  }
  if data[0].to_int() != 0x16 {
    return Err(NotTlsHandshake)
  }
  guard read_u16_int(data, 3) is Some(record_len) else {
    return Err(BadLength(field="record.length", offset=3))
  }
  if record_len < 4 {
    return Err(BadLength(field="handshake.header", offset=5))
  }
  let record_end = 5 + record_len
  if record_end < 5 || data.length() < record_end {
    return Err(IncompleteRecord(expected=record_end, available=data.length()))
  }
  if data[5].to_int() != 15 {
    return Err(BadHandshakeType(data[5].to_int()))
  }
  guard read_u24_int(data, 6) is Some(handshake_len) else {
    return Err(BadLength(field="handshake.length", offset=6))
  }
  let body_offset = 9
  let body_end = body_offset + handshake_len
  if handshake_len < 0 || body_end < body_offset || body_end > record_end {
    return Err(BadLength(field="handshake.body", offset=body_offset))
  }

  // CertificateVerify: Signature Algorithm (2 bytes) + Signature Length (2 bytes) + Signature
  if handshake_len < 4 {
    return Err(BadLength(field="cert_verify.header", offset=body_offset))
  }

  guard read_u16(data, body_offset) is Some(signature_algorithm) else {
    return Err(BadLength(field="cert_verify.sig_alg", offset=body_offset))
  }

  guard read_u16_int(data, body_offset + 2) is Some(sig_len) else {
    return Err(BadLength(field="cert_verify.sig_len", offset=body_offset + 2))
  }

  if sig_len < 0 ||
    body_offset + 4 + sig_len > body_end ||
    !has_range(data, body_offset + 4, sig_len) {
    return Err(BadLength(field="cert_verify.signature", offset=body_offset + 4))
  }

  let sig_arr = Array::new(capacity=sig_len)
  for i in 0..<sig_len {
    sig_arr.push(data[body_offset + 4 + i])
  }
  let signature = Bytes::from_array(sig_arr)

  Ok({ signature_algorithm, signature })
}

///|
pub fn parse_finished(data : BytesView) -> Result[Finished, ParseError] {
  if data.length() < 5 {
    return Err(IncompleteRecord(expected=5, available=data.length()))
  }
  if data[0].to_int() != 0x16 {
    return Err(NotTlsHandshake)
  }
  guard read_u16_int(data, 3) is Some(record_len) else {
    return Err(BadLength(field="record.length", offset=3))
  }
  if record_len < 4 {
    return Err(BadLength(field="handshake.header", offset=5))
  }
  let record_end = 5 + record_len
  if record_end < 5 || data.length() < record_end {
    return Err(IncompleteRecord(expected=record_end, available=data.length()))
  }
  if data[5].to_int() != 20 {
    return Err(BadHandshakeType(data[5].to_int()))
  }
  guard read_u24_int(data, 6) is Some(handshake_len) else {
    return Err(BadLength(field="handshake.length", offset=6))
  }
  let body_offset = 9
  let body_end = body_offset + handshake_len
  if handshake_len < 0 ||
    body_end < body_offset ||
    body_end > record_end ||
    !has_range(data, body_offset, handshake_len) {
    return Err(BadLength(field="handshake.body", offset=body_offset))
  }

  let verify_arr = Array::new(capacity=handshake_len)
  for i in 0..<handshake_len {
    verify_arr.push(data[body_offset + i])
  }
  let verify_data = Bytes::from_array(verify_arr)

  Ok({ verify_data, })
}
