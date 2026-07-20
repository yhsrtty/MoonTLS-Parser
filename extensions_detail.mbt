// Deep TLS Extension parsing details

///|
pub struct KeyShareEntry {
  group : UInt16
  key_exchange : Bytes
} derive(Debug, Eq)

///|
pub struct KeyShareClient {
  client_shares : Array[KeyShareEntry]
} derive(Debug, Eq)

///|
pub struct KeyShareServer {
  server_share : KeyShareEntry
} derive(Debug, Eq)

///|
pub struct SupportedVersionsClient {
  versions : Array[UInt16]
} derive(Debug, Eq)

///|
pub struct ServerNameEntry {
  name_type : Byte
  name : String
} derive(Debug, Eq)

///|
pub struct ServerNameList {
  names : Array[ServerNameEntry]
} derive(Debug, Eq)

///|
pub struct TlsCookie {
  cookie : Bytes
} derive(Debug, Eq)

///|
pub fn parse_key_share_client(
  data : BytesView,
) -> Result[KeyShareClient, ParseError] {
  if data.length() < 2 {
    return Err(BadLength(field="key_share.client_length", offset=0))
  }
  guard read_u16_int(data, 0) is Some(shares_len) else {
    return Err(BadLength(field="key_share.client_length", offset=0))
  }
  if shares_len < 0 || shares_len + 2 > data.length() {
    return Err(BadLength(field="key_share.client_body", offset=2))
  }
  let shares : Array[KeyShareEntry] = []
  let mut cursor = 2
  let end = 2 + shares_len
  while cursor + 4 <= end {
    guard read_u16(data, cursor) is Some(group) else {
      return Err(BadLength(field="key_share.client_group", offset=cursor))
    }
    guard read_u16_int(data, cursor + 2) is Some(key_len) else {
      return Err(BadLength(field="key_share.client_key_len", offset=cursor + 2))
    }
    cursor = cursor + 4
    if key_len < 0 ||
      cursor + key_len > end ||
      !has_range(data, cursor, key_len) {
      return Err(BadLength(field="key_share.client_key_body", offset=cursor))
    }
    let key_arr = Array::new(capacity=key_len)
    for i in 0..<key_len {
      key_arr.push(data[cursor + i])
    }
    let key_exchange = Bytes::from_array(key_arr)
    shares.push({ group, key_exchange })
    cursor = cursor + key_len
  }
  Ok({ client_shares: shares })
}

///|
pub fn parse_key_share_server(
  data : BytesView,
) -> Result[KeyShareServer, ParseError] {
  if data.length() < 4 {
    return Err(BadLength(field="key_share.server_header", offset=0))
  }
  guard read_u16(data, 0) is Some(group) else {
    return Err(BadLength(field="key_share.server_group", offset=0))
  }
  guard read_u16_int(data, 2) is Some(key_len) else {
    return Err(BadLength(field="key_share.server_key_len", offset=2))
  }
  if key_len < 0 || 4 + key_len > data.length() || !has_range(data, 4, key_len) {
    return Err(BadLength(field="key_share.server_body", offset=4))
  }
  let key_arr = Array::new(capacity=key_len)
  for i in 0..<key_len {
    key_arr.push(data[4 + i])
  }
  let key_exchange = Bytes::from_array(key_arr)
  let server_share = { group, key_exchange }
  Ok({ server_share, })
}

///|
pub fn parse_supported_versions_client(
  data : BytesView,
) -> Result[SupportedVersionsClient, ParseError] {
  if data.length() < 1 {
    return Err(BadLength(field="supported_versions.client_length", offset=0))
  }
  let len = data[0].to_int()
  if len < 0 || len + 1 > data.length() || len % 2 != 0 {
    return Err(BadLength(field="supported_versions.client_body", offset=1))
  }
  let versions : Array[UInt16] = []
  let mut cursor = 1
  let end = 1 + len
  while cursor + 2 <= end {
    guard read_u16(data, cursor) is Some(ver) else {
      return Err(
        BadLength(field="supported_versions.client_version", offset=cursor),
      )
    }
    if !is_grease(ver) {
      versions.push(ver)
    }
    cursor = cursor + 2
  }
  Ok({ versions, })
}

///|
pub fn parse_server_name_list(
  data : BytesView,
) -> Result[ServerNameList, ParseError] {
  if data.length() < 2 {
    return Err(BadLength(field="sni.list_len", offset=0))
  }
  guard read_u16_int(data, 0) is Some(list_len) else {
    return Err(BadLength(field="sni.list_len", offset=0))
  }
  if list_len < 0 || list_len + 2 > data.length() {
    return Err(BadLength(field="sni.list_body", offset=2))
  }
  let names : Array[ServerNameEntry] = []
  let mut cursor = 2
  let end = 2 + list_len
  while cursor + 3 <= end {
    let name_type = data[cursor]
    guard read_u16_int(data, cursor + 1) is Some(name_len) else {
      return Err(BadLength(field="sni.name_len", offset=cursor + 1))
    }
    cursor = cursor + 3
    if name_len < 0 ||
      cursor + name_len > end ||
      !has_range(data, cursor, name_len) {
      return Err(BadLength(field="sni.name_body", offset=cursor))
    }
    match bytes_to_ascii(data, cursor, name_len) {
      Some(name) => names.push({ name_type, name })
      None => ()
    }
    cursor = cursor + name_len
  }
  Ok({ names, })
}

///|
pub fn parse_tls_cookie(data : BytesView) -> Result[TlsCookie, ParseError] {
  if data.length() < 2 {
    return Err(BadLength(field="cookie.len", offset=0))
  }
  guard read_u16_int(data, 0) is Some(cookie_len) else {
    return Err(BadLength(field="cookie.len", offset=0))
  }
  if cookie_len < 0 ||
    cookie_len + 2 > data.length() ||
    !has_range(data, 2, cookie_len) {
    return Err(BadLength(field="cookie.body", offset=2))
  }
  let cookie_arr = Array::new(capacity=cookie_len)
  for i in 0..<cookie_len {
    cookie_arr.push(data[2 + i])
  }
  let cookie = Bytes::from_array(cookie_arr)
  Ok({ cookie, })
}
