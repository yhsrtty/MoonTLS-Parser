///|
pub fn parse_server_hello(data : BytesView) -> Result[ServerHello, ParseError] {
  if data.length() < 5 {
    return Err(IncompleteRecord(expected=5, available=data.length()))
  }
  if data[0].to_int() != 0x16 {
    return Err(NotTlsHandshake)
  }
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
  if data[5].to_int() != 2 {
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

  // ServerHello minimum size check:
  // Version (2) + Random (32) + SessionID len (1) = 35 bytes
  if body_end - body_offset < 35 {
    return Err(BadLength(field="serverhello.fixed", offset=body_offset))
  }

  guard read_u16(data, body_offset) is Some(initial_version) else {
    return Err(BadLength(field="server.version", offset=body_offset))
  }
  let mut version = initial_version

  let random_arr = Array::new(capacity=32)
  for i in 0..<32 {
    random_arr.push(data[body_offset + 2 + i])
  }
  let random_bytes = Bytes::from_array(random_arr)

  let mut cursor = body_offset + 34
  guard read_u8(data, cursor) is Some(session_len) else {
    return Err(BadLength(field="session_id.length", offset=cursor))
  }

  if cursor + 1 + session_len > body_end {
    return Err(BadLength(field="session_id.body", offset=cursor))
  }
  let session_arr = Array::new(capacity=session_len)
  for i in 0..<session_len {
    session_arr.push(data[cursor + 1 + i])
  }
  let session_bytes = Bytes::from_array(session_arr)
  cursor = cursor + 1 + session_len

  // Cipher Suite (2) + Compression Method (1) = 3 bytes
  if cursor + 3 > body_end {
    return Err(BadLength(field="cipher_and_compression.header", offset=cursor))
  }
  guard read_u16(data, cursor) is Some(cipher_suite) else {
    return Err(BadLength(field="cipher_suite", offset=cursor))
  }
  let compression_method = data[cursor + 2]
  cursor = cursor + 3

  let extensions : Array[UInt16] = []
  let mut selected_alpn : String? = None

  if cursor < body_end {
    if cursor + 2 > body_end {
      return Err(BadLength(field="extensions.length", offset=cursor))
    }
    guard read_u16_int(data, cursor) is Some(ext_total_len) else {
      return Err(BadLength(field="extensions.length", offset=cursor))
    }
    cursor = cursor + 2
    if cursor + ext_total_len > body_end {
      return Err(BadLength(field="extensions.body", offset=cursor))
    }
    let ext_end = cursor + ext_total_len
    while cursor + 4 <= ext_end {
      guard read_u16(data, cursor) is Some(ext_type) else {
        return Err(BadLength(field="extension.type", offset=cursor))
      }
      guard read_u16_int(data, cursor + 2) is Some(ext_len) else {
        return Err(BadLength(field="extension.length", offset=cursor + 2))
      }
      cursor = cursor + 4
      if cursor + ext_len > ext_end {
        return Err(BadLength(field="extension.body", offset=cursor))
      }
      if !is_grease(ext_type) {
        extensions.push(ext_type)
      }
      // ALPN Extension Type is 16
      if ext_type.to_int() == 16 {
        selected_alpn = parse_server_alpn(data[cursor:cursor + ext_len])
      }
      // Supported Versions Extension Type is 43
      if ext_type.to_int() == 43 {
        if ext_len == 2 {
          guard read_u16(data, cursor) is Some(negotiated_version) else {
            return Err(
              BadLength(field="supported_versions.negotiated", offset=cursor),
            )
          }
          version = negotiated_version
        }
      }
      cursor = cursor + ext_len
    }
  }

  Ok({
    version,
    random: random_bytes,
    session_id: session_bytes,
    cipher_suite,
    compression_method,
    extensions,
    selected_alpn,
    raw_length: record_end,
  })
}

///|
fn parse_server_alpn(data : BytesView) -> String? {
  // Server-side ALPN selection contains list of protocol names (usually just one)
  // Layout: ALPN extension data length (2 bytes) + 1 byte name length + name
  if data.length() < 3 {
    return None
  }
  guard read_u16_int(data, 0) is Some(list_len) else { return None }
  if list_len + 2 > data.length() {
    return None
  }
  let len = data[2].to_int()
  if len + 3 > data.length() {
    return None
  }
  bytes_to_ascii(data, 3, len)
}

///|
pub fn ServerHello::ja4s_a(self : ServerHello) -> String {
  let ver_str = match self.version.to_int() {
    0x0304 => "s13"
    0x0303 => "s12"
    0x0302 => "s11"
    0x0301 => "s10"
    _ => "s00"
  }
  let alpn_str = if self.selected_alpn is Some(_) { "a" } else { "n" }
  let ext_count = self.extensions.filter(fn(v) { !is_grease(v) }).length()
  "\{ver_str}\{alpn_str}\{ext_count.to_string().pad_start(2, '0')}"
}
