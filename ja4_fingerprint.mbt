// JA4 and JA4S Client/Server Fingerprinting implementation

///|
fn sort_u16(arr : Array[UInt16]) -> Array[UInt16] {
  let out = Array::new(capacity=arr.length())
  for v in arr {
    out.push(v)
  }
  let len = out.length()
  for i in 0..<len {
    let mut min_idx = i
    for j in (i + 1)..<len {
      if out[j] < out[min_idx] {
        min_idx = j
      }
    }
    if min_idx != i {
      let temp = out[i]
      out[i] = out[min_idx]
      out[min_idx] = temp
    }
  }
  out
}

///|
fn format_u16_hex_list(arr : Array[UInt16]) -> String {
  let parts : Array[String] = []
  for v in arr {
    parts.push(uint16_to_hex4(v))
  }
  parts.join(",")
}

///|
pub fn ClientHello::ja4_a_str(self : ClientHello) -> String {
  let ver_str = match self.record_version.to_int() {
    0x0304 => "13"
    0x0303 => "12"
    0x0302 => "11"
    0x0301 => "10"
    _ => "12"
  }
  let sni_mark = if self.server_name is Some(_) { "d" } else { "i" }
  let active_ciphers = self.cipher_suites.filter(fn(v) { !is_grease(v) })
  let cipher_count = active_ciphers.length()
  let active_exts = self.extensions.filter(fn(v) { !is_grease(v) })
  let ext_count = active_exts.length()
  let alpn_str = if self.alpn_protocols.length() > 0 {
    let first = self.alpn_protocols[0]
    if first.length() >= 2 {
      first[0:2]
    } else if first.length() == 1 {
      first + "0"
    } else {
      "00"
    }
  } else {
    "00"
  }
  let cc = if cipher_count >= 99 {
    "99"
  } else {
    cipher_count.to_string().pad_start(2, '0')
  }
  let ec = if ext_count >= 99 {
    "99"
  } else {
    ext_count.to_string().pad_start(2, '0')
  }
  "t\{ver_str}\{sni_mark}\{cc}\{ec}\{alpn_str}"
}

///|
pub fn ClientHello::ja4_b_str(self : ClientHello) -> String {
  let active_ciphers = self.cipher_suites.filter(fn(v) { !is_grease(v) })
  let sorted = sort_u16(active_ciphers)
  let formatted = format_u16_hex_list(sorted)
  let hash = sha256_hex(ascii_bytes(formatted))
  if hash.length() >= 12 {
    hash[0:12].to_owned()
  } else {
    hash
  }
}

///|
pub fn ClientHello::ja4_c_str(self : ClientHello) -> String {
  let active_exts = self.extensions.filter(fn(v) { !is_grease(v) })
  let sorted_exts = sort_u16(active_exts)
  let formatted_exts = format_u16_hex_list(sorted_exts)

  let active_sigs = self.signature_algorithms.filter(fn(v) { !is_grease(v) })
  let sorted_sigs = sort_u16(active_sigs)
  let formatted_sigs = format_u16_hex_list(sorted_sigs)

  let formatted = "\{formatted_exts}_\{formatted_sigs}"
  let hash = sha256_hex(ascii_bytes(formatted))
  if hash.length() >= 12 {
    hash[0:12].to_owned()
  } else {
    hash
  }
}

///|
pub fn ClientHello::ja4(self : ClientHello) -> String {
  self.ja4_a_str() + "_" + self.ja4_b_str() + "_" + self.ja4_c_str()
}

///|
pub fn ServerHello::ja4s_a_str(self : ServerHello) -> String {
  let ver_str = match self.version.to_int() {
    0x0304 => "13"
    0x0303 => "12"
    0x0302 => "11"
    0x0301 => "10"
    _ => "12"
  }
  let alpn_str = if self.selected_alpn is Some(al) {
    if al.length() >= 2 {
      al[0:2]
    } else if al.length() == 1 {
      al + "0"
    } else {
      "00"
    }
  } else {
    "00"
  }
  let active_exts = self.extensions.filter(fn(v) { !is_grease(v) })
  let ext_count = active_exts.length()
  let ec = if ext_count >= 99 {
    "99"
  } else {
    ext_count.to_string().pad_start(2, '0')
  }
  "s\{ver_str}s\{alpn_str}\{ec}"
}

///|
pub fn ServerHello::ja4s_b_str(self : ServerHello) -> String {
  uint16_to_hex4(self.cipher_suite)
}

///|
pub fn ServerHello::ja4s_c_str(self : ServerHello) -> String {
  let active_exts = self.extensions.filter(fn(v) { !is_grease(v) })
  let sorted = sort_u16(active_exts)
  let formatted = format_u16_hex_list(sorted)
  let hash = sha256_hex(ascii_bytes(formatted))
  if hash.length() >= 12 {
    hash[0:12].to_owned()
  } else {
    hash
  }
}

///|
pub fn ServerHello::ja4s(self : ServerHello) -> String {
  self.ja4s_a_str() + "_" + self.ja4s_b_str() + "_" + self.ja4s_c_str()
}
