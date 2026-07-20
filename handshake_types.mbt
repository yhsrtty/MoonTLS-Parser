// Parsing implementations for additional TLS Handshake message types

///|

///|
pub fn parse_client_key_exchange(
  data : BytesView,
) -> Result[ClientKeyExchange, ParseError] {
  if data.length() < 9 {
    return Err(IncompleteRecord(expected=9, available=data.length()))
  }
  if data[0].to_int() != 0x16 {
    return Err(NotTlsHandshake)
  }
  if data[5].to_int() != 16 {
    return Err(BadHandshakeType(data[5].to_int()))
  }
  guard read_u24_int(data, 6) is Some(handshake_len) else {
    return Err(BadLength(field="handshake.length", offset=6))
  }
  let body_offset = 9
  let body_end = body_offset + handshake_len
  if handshake_len < 0 ||
    body_end < body_offset ||
    body_end > data.length() ||
    !has_range(data, body_offset, handshake_len) {
    return Err(BadLength(field="handshake.body", offset=body_offset))
  }

  let raw_arr = Array::new(capacity=handshake_len)
  for i in 0..<handshake_len {
    raw_arr.push(data[body_offset + i])
  }
  let raw = Bytes::from_array(raw_arr)
  Ok({ raw, })
}

///|
pub fn parse_server_key_exchange(
  data : BytesView,
) -> Result[ServerKeyExchange, ParseError] {
  if data.length() < 9 {
    return Err(IncompleteRecord(expected=9, available=data.length()))
  }
  if data[0].to_int() != 0x16 {
    return Err(NotTlsHandshake)
  }
  if data[5].to_int() != 12 {
    return Err(BadHandshakeType(data[5].to_int()))
  }
  guard read_u24_int(data, 6) is Some(handshake_len) else {
    return Err(BadLength(field="handshake.length", offset=6))
  }
  let body_offset = 9
  let body_end = body_offset + handshake_len
  if handshake_len < 0 ||
    body_end < body_offset ||
    body_end > data.length() ||
    !has_range(data, body_offset, handshake_len) {
    return Err(BadLength(field="handshake.body", offset=body_offset))
  }

  let raw_arr = Array::new(capacity=handshake_len)
  for i in 0..<handshake_len {
    raw_arr.push(data[body_offset + i])
  }
  let raw = Bytes::from_array(raw_arr)
  Ok({ raw, })
}

///|
pub fn parse_new_session_ticket(
  data : BytesView,
) -> Result[NewSessionTicket, ParseError] {
  if data.length() < 9 {
    return Err(IncompleteRecord(expected=9, available=data.length()))
  }
  if data[0].to_int() != 0x16 {
    return Err(NotTlsHandshake)
  }
  if data[5].to_int() != 4 {
    return Err(BadHandshakeType(data[5].to_int()))
  }
  guard read_u24_int(data, 6) is Some(handshake_len) else {
    return Err(BadLength(field="handshake.length", offset=6))
  }
  let body_offset = 9
  let body_end = body_offset + handshake_len
  if handshake_len < 0 || body_end < body_offset || body_end > data.length() {
    return Err(BadLength(field="handshake.body", offset=body_offset))
  }

  // NewSessionTicket layout:
  // Ticket Lifetime (4 bytes) + Ticket Age Add (4 bytes) + Ticket Length (2 bytes) + Ticket
  if handshake_len < 10 {
    return Err(BadLength(field="ticket.header", offset=body_offset))
  }

  guard read_u32_int(data, body_offset) is Some(lifetime) else {
    return Err(BadLength(field="ticket.lifetime", offset=body_offset))
  }
  guard read_u32_int(data, body_offset + 4) is Some(age_add) else {
    return Err(BadLength(field="ticket.age_add", offset=body_offset + 4))
  }
  guard read_u16_int(data, body_offset + 8) is Some(ticket_len) else {
    return Err(BadLength(field="ticket.length", offset=body_offset + 8))
  }

  if ticket_len < 0 ||
    body_offset + 10 + ticket_len > body_end ||
    !has_range(data, body_offset + 10, ticket_len) {
    return Err(BadLength(field="ticket.body", offset=body_offset + 10))
  }

  let ticket_arr = Array::new(capacity=ticket_len)
  for i in 0..<ticket_len {
    ticket_arr.push(data[body_offset + 10 + i])
  }
  let ticket = Bytes::from_array(ticket_arr)

  Ok({
    lifetime: lifetime.reinterpret_as_uint(),
    age_add: age_add.reinterpret_as_uint(),
    ticket,
  })
}

///|
pub fn parse_encrypted_extensions(
  data : BytesView,
) -> Result[EncryptedExtensions, ParseError] {
  if data.length() < 9 {
    return Err(IncompleteRecord(expected=9, available=data.length()))
  }
  if data[0].to_int() != 0x16 {
    return Err(NotTlsHandshake)
  }
  if data[5].to_int() != 8 {
    return Err(BadHandshakeType(data[5].to_int()))
  }
  guard read_u24_int(data, 6) is Some(handshake_len) else {
    return Err(BadLength(field="handshake.length", offset=6))
  }
  let body_offset = 9
  let body_end = body_offset + handshake_len
  if handshake_len < 0 || body_end < body_offset || body_end > data.length() {
    return Err(BadLength(field="handshake.body", offset=body_offset))
  }

  if handshake_len < 2 {
    return Err(BadLength(field="encrypted_extensions.len", offset=body_offset))
  }

  guard read_u16_int(data, body_offset) is Some(ext_total_len) else {
    return Err(
      BadLength(field="encrypted_extensions.length", offset=body_offset),
    )
  }

  if ext_total_len < 0 || body_offset + 2 + ext_total_len > body_end {
    return Err(
      BadLength(field="encrypted_extensions.body", offset=body_offset + 2),
    )
  }

  let extensions : Array[UInt16] = []
  let mut cursor = body_offset + 2
  let ext_end = cursor + ext_total_len

  while cursor + 4 <= ext_end {
    guard read_u16(data, cursor) is Some(ext_type) else {
      return Err(BadLength(field="extension.type", offset=cursor))
    }
    guard read_u16_int(data, cursor + 2) is Some(ext_len) else {
      return Err(BadLength(field="extension.length", offset=cursor + 2))
    }
    cursor = cursor + 4
    if ext_len < 0 ||
      cursor + ext_len > ext_end ||
      !has_range(data, cursor, ext_len) {
      return Err(BadLength(field="extension.body", offset=cursor))
    }
    if !is_grease(ext_type) {
      extensions.push(ext_type)
    }
    cursor = cursor + ext_len
  }

  Ok({ extensions, })
}

///|
fn read_u32_int(data : BytesView, offset : Int) -> Int? {
  if has_range(data, offset, 4) {
    let val = data[offset].to_int() * 16777216 +
      data[offset + 1].to_int() * 65536 +
      data[offset + 2].to_int() * 256 +
      data[offset + 3].to_int()
    Some(val)
  } else {
    None
  }
}
