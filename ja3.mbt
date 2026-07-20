///|
pub fn normalize_u16_list(values : ArrayView[UInt16]) -> String {
  let parts : Array[String] = []
  for v in values {
    if !is_grease(v) {
      parts.push(v.to_int().to_string())
    }
  }
  parts.join("-")
}

///|
fn normalize_byte_list(values : ArrayView[Byte]) -> String {
  let parts : Array[String] = []
  for v in values {
    parts.push(v.to_int().to_string())
  }
  parts.join("-")
}

///|
pub fn ClientHello::ja3_string(self : ClientHello) -> String {
  [
    self.legacy_version.to_int().to_string(),
    normalize_u16_list(self.cipher_suites),
    normalize_u16_list(self.extensions),
    normalize_u16_list(self.supported_groups),
    normalize_byte_list(self.ec_point_formats),
  ].join(",")
}

///|
pub fn ascii_bytes(text : String) -> Bytes {
  let out : Array[Byte] = []
  for unit in text.code_units() {
    out.push(unit.to_byte())
  }
  Bytes::from_array(out)
}

///|
fn md5_hex(text : String) -> String {
  let digest = @crypto.md5(ascii_bytes(text))
  let out = StringBuilder()
  for b in digest {
    out.write_string(b.to_hex())
  }
  out.to_string()
}

///|
pub fn ClientHello::ja3_digest(self : ClientHello) -> String {
  md5_hex(self.ja3_string())
}

///|
pub fn ClientHello::ja4_a(self : ClientHello) -> String {
  let sni_mark = if self.server_name is Some(_) { "d" } else { "i" }
  let cipher_count = self.cipher_suites.filter(fn(v) { !is_grease(v) }).length()
  let ext_count = self.extensions.filter(fn(v) { !is_grease(v) }).length()
  "t13\{sni_mark}\{cipher_count.to_string().pad_start(2, '0')}\{ext_count.to_string().pad_start(2, '0')}"
}
