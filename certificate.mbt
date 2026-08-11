///|
pub fn parse_certificate(
  data : BytesView,
) -> Result[TlsCertificate, ParseError] {
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
  if record_len < 0 {
    return Err(BadLength(field="record.length", offset=3))
  }
  let record_end = 5 + record_len
  if record_end < 5 || data.length() < record_end {
    return Err(IncompleteRecord(expected=record_end, available=data.length()))
  }
  if record_len < 4 {
    return Err(BadLength(field="handshake.header", offset=5))
  }
  if data[5].to_int() != 11 {
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

  // Certificates list length is 3 bytes
  if body_end - body_offset < 3 {
    return Err(BadLength(field="certificates.list_length", offset=body_offset))
  }
  guard read_u24_int(data, body_offset) is Some(certs_list_len) else {
    return Err(BadLength(field="certificates.list_length", offset=body_offset))
  }

  let mut cursor = body_offset + 3
  let list_end = cursor + certs_list_len
  if certs_list_len < 0 || list_end < cursor || list_end > body_end {
    return Err(BadLength(field="certificates.list_body", offset=cursor))
  }
  if list_end != body_end {
    return Err(BadLength(field="certificates.trailing", offset=list_end))
  }

  let cert_lengths : Array[Int] = []

  while cursor + 3 <= list_end {
    guard read_u24_int(data, cursor) is Some(cert_len) else {
      return Err(BadLength(field="certificate.length", offset=cursor))
    }
    cursor = cursor + 3
    if cert_len < 0 || cursor + cert_len > list_end {
      return Err(BadLength(field="certificate.body", offset=cursor))
    }
    cert_lengths.push(cert_len)
    cursor = cursor + cert_len
  }

  if cursor != list_end {
    return Err(BadLength(field="certificates.trailing", offset=cursor))
  }

  Ok({ cert_lengths, })
}
