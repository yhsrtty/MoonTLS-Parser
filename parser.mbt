///|
fn parse_extensions(
  data : BytesView,
  offset : Int,
  total_len : Int,
  hello : ClientHello,
) -> Result[ClientHello, ParseError] {
  let mut cursor = offset
  let end = offset + total_len
  let mut current = hello
  while cursor + 4 <= end {
    guard read_u16(data, cursor) is Some(ext_type) else {
      return Err(BadLength(field="extension.type", offset=cursor))
    }
    guard read_u16_int(data, cursor + 2) is Some(ext_len) else {
      return Err(BadLength(field="extension.length", offset=cursor + 2))
    }
    cursor = cursor + 4
    if cursor + ext_len > end {
      return Err(BadLength(field="extension.body", offset=cursor))
    }
    if !is_grease(ext_type) {
      current.extensions.push(ext_type)
    }
    let body = data[cursor:cursor + ext_len]
    match ext_type.to_int() {
      0 => current = { ..current, server_name: parse_sni(body) }
      10 => current = { ..current, supported_groups: parse_u16_vector(body) }
      11 => current = { ..current, ec_point_formats: parse_byte_vector(body) }
      13 =>
        current = { ..current, signature_algorithms: parse_u16_vector(body) }
      16 => current = { ..current, alpn_protocols: parse_alpn(body) }
      _ => ()
    }
    cursor = cursor + ext_len
  }
  if cursor == end {
    Ok(current)
  } else {
    Err(BadLength(field="extensions.trailing", offset=cursor))
  }
}

///|
pub fn parse_client_hello(data : BytesView) -> Result[ClientHello, ParseError] {
  if data.length() < 5 {
    return Err(IncompleteRecord(expected=5, available=data.length()))
  }
  if data[0].to_int() != 0x16 {
    return Err(NotTlsHandshake)
  }
  guard read_u16(data, 1) is Some(record_version) else {
    return Err(BadLength(field="record.version", offset=1))
  }
  if record_version.to_int() < 0x0301 || record_version.to_int() > 0x0304 {
    return Err(UnsupportedRecordVersion(record_version))
  }
  guard read_u16_int(data, 3) is Some(record_len) else {
    return Err(BadLength(field="record.length", offset=3))
  }
  let record_end = 5 + record_len
  if data.length() < record_end {
    return Err(IncompleteRecord(expected=record_end, available=data.length()))
  }
  if data[5].to_int() != 1 {
    return Err(BadHandshakeType(data[5].to_int()))
  }
  guard read_u24_int(data, 6) is Some(handshake_len) else {
    return Err(BadLength(field="handshake.length", offset=6))
  }
  let body_offset = 9
  let body_end = body_offset + handshake_len
  if body_end > record_end {
    return Err(BadLength(field="handshake.body", offset=body_offset))
  }
  guard require_range(data, body_offset, 34, "clienthello.fixed") is Ok(_) else {
    return Err(BadLength(field="clienthello.fixed", offset=body_offset))
  }
  guard read_u16(data, body_offset) is Some(legacy_version) else {
    return Err(BadLength(field="client.version", offset=body_offset))
  }
  let mut cursor = body_offset + 34
  guard read_u8(data, cursor) is Some(session_len) else {
    return Err(BadLength(field="session_id.length", offset=cursor))
  }
  cursor = cursor + 1 + session_len
  guard read_u16_int(data, cursor) is Some(cipher_len) else {
    return Err(BadLength(field="cipher_suites.length", offset=cursor))
  }
  cursor = cursor + 2
  if cursor + cipher_len > body_end || cipher_len % 2 != 0 {
    return Err(BadLength(field="cipher_suites.body", offset=cursor))
  }
  let cipher_suites : Array[UInt16] = []
  let mut c = cursor
  while c + 1 < cursor + cipher_len {
    match read_u16(data, c) {
      Some(v) => if !is_grease(v) { cipher_suites.push(v) }
      None => ()
    }
    c = c + 2
  }
  cursor = cursor + cipher_len
  guard read_u8(data, cursor) is Some(compression_len) else {
    return Err(BadLength(field="compression.length", offset=cursor))
  }
  cursor = cursor + 1
  if cursor + compression_len > body_end {
    return Err(BadLength(field="compression.body", offset=cursor))
  }
  let compression_methods : Array[Byte] = []
  for i in 0..<compression_len {
    compression_methods.push(data[cursor + i])
  }
  cursor = cursor + compression_len
  let base = {
    legacy_version,
    record_version,
    cipher_suites,
    compression_methods,
    extensions: [],
    supported_groups: [],
    ec_point_formats: [],
    signature_algorithms: [],
    alpn_protocols: [],
    server_name: None,
    raw_length: record_end,
  }
  if cursor == body_end {
    return Ok(base)
  }
  guard read_u16_int(data, cursor) is Some(ext_total_len) else {
    return Err(BadLength(field="extensions.length", offset=cursor))
  }
  cursor = cursor + 2
  if cursor + ext_total_len > body_end {
    return Err(BadLength(field="extensions.body", offset=cursor))
  }
  parse_extensions(data, cursor, ext_total_len, base)
}

///|
pub fn ClientHelloStream::push(
  self : ClientHelloStream,
  chunk : BytesView,
) -> StreamResult {
  for b in chunk {
    self.buffer.push(b)
  }
  let data = Bytes::from_array(self.buffer)
  match parse_client_hello(data) {
    Ok(hello) => {
      self.buffer.clear()
      Parsed(hello)
    }
    Err(IncompleteRecord(_)) => NeedMore
    Err(e) => {
      self.buffer.clear()
      Rejected(e)
    }
  }
}

///|
pub fn parse_tls_record(data : BytesView) -> Result[TlsRecord, ParseError] {
  if data.length() < 5 {
    return Err(IncompleteRecord(expected=5, available=data.length()))
  }
  let ct = data[0].to_int()
  guard read_u16(data, 1) is Some(_) else {
    return Err(BadLength(field="record.version", offset=1))
  }
  guard read_u16_int(data, 3) is Some(record_len) else {
    return Err(BadLength(field="record.length", offset=3))
  }
  let record_end = 5 + record_len
  if data.length() < record_end {
    return Err(IncompleteRecord(expected=record_end, available=data.length()))
  }

  let body = data[0:record_end]
  match ct {
    0x14 =>
      Ok(
        GenericRecord(
          ChangeCipherSpec,
          Bytes::from_array(self_bytes(data, 5, record_len)),
        ),
      )
    0x15 =>
      match parse_alert(body) {
        Ok(alert) => Ok(AlertRecord(alert))
        Err(e) => Err(e)
      }
    0x16 => {
      if record_len < 1 {
        return Err(BadLength(field="handshake.type", offset=5))
      }
      let handshake_type = data[5].to_int()
      match handshake_type {
        1 =>
          match parse_client_hello(body) {
            Ok(hello) => Ok(ClientHelloRecord(hello))
            Err(e) => Err(e)
          }
        2 =>
          match parse_server_hello(body) {
            Ok(hello) => Ok(ServerHelloRecord(hello))
            Err(e) => Err(e)
          }
        11 =>
          match parse_certificate(body) {
            Ok(cert) => Ok(CertificateRecord(cert))
            Err(e) => Err(e)
          }
        _ =>
          Ok(
            GenericRecord(
              Handshake,
              Bytes::from_array(self_bytes(data, 5, record_len)),
            ),
          )
      }
    }
    0x17 =>
      Ok(
        GenericRecord(
          ApplicationData,
          Bytes::from_array(self_bytes(data, 5, record_len)),
        ),
      )
    _ =>
      Ok(
        GenericRecord(
          Unknown(data[0]),
          Bytes::from_array(self_bytes(data, 5, record_len)),
        ),
      )
  }
}

///|
fn self_bytes(data : BytesView, offset : Int, len : Int) -> Array[Byte] {
  let out = Array::new(capacity=len)
  for i in 0..<len {
    out.push(data[offset + i])
  }
  out
}
