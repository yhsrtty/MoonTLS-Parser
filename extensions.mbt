///|
fn parse_sni(data : BytesView) -> String? {
  guard read_u16_int(data, 0) is Some(list_len) else { return None }
  if list_len + 2 > data.length() {
    return None
  }
  let mut offset = 2
  while offset + 3 <= 2 + list_len {
    let name_type = data[offset].to_int()
    guard read_u16_int(data, offset + 1) is Some(name_len) else { return None }
    offset = offset + 3
    if offset + name_len > data.length() {
      return None
    }
    if name_type == 0 {
      return bytes_to_ascii(data, offset, name_len)
    }
    offset = offset + name_len
  }
  None
}

///|
fn parse_alpn(data : BytesView) -> Array[String] {
  let out : Array[String] = []
  guard read_u16_int(data, 0) is Some(total_len) else { return out }
  let mut offset = 2
  let end = Int::min(data.length(), 2 + total_len)
  while offset < end {
    let len = data[offset].to_int()
    offset = offset + 1
    if offset + len > end {
      return out
    }
    match bytes_to_ascii(data, offset, len) {
      Some(p) => out.push(p)
      None => ()
    }
    offset = offset + len
  }
  out
}

///|
fn parse_u16_vector(data : BytesView) -> Array[UInt16] {
  let out : Array[UInt16] = []
  guard read_u16_int(data, 0) is Some(total_len) else { return out }
  let mut offset = 2
  let end = Int::min(data.length(), 2 + total_len)
  while offset + 1 < end {
    match read_u16(data, offset) {
      Some(v) => out.push(v)
      None => ()
    }
    offset = offset + 2
  }
  out
}

///|
fn parse_byte_vector(data : BytesView) -> Array[Byte] {
  let out : Array[Byte] = []
  if data.length() == 0 {
    return out
  }
  let len = data[0].to_int()
  let end = Int::min(data.length(), 1 + len)
  for i in 1..<end {
    out.push(data[i])
  }
  out
}
