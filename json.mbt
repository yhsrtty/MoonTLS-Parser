///|
fn json_array_u16(arr : Array[UInt16]) -> String {
  let sb = StringBuilder()
  sb.write_string("[")
  for i in 0..<arr.length() {
    if i > 0 {
      sb.write_string(",")
    }
    sb.write_string(arr[i].to_int().to_string())
  }
  sb.write_string("]")
  sb.to_string()
}

///|
fn json_array_byte(arr : Array[Byte]) -> String {
  let sb = StringBuilder()
  sb.write_string("[")
  for i in 0..<arr.length() {
    if i > 0 {
      sb.write_string(",")
    }
    sb.write_string(arr[i].to_int().to_string())
  }
  sb.write_string("]")
  sb.to_string()
}

///|
fn json_array_int(arr : Array[Int]) -> String {
  let sb = StringBuilder()
  sb.write_string("[")
  for i in 0..<arr.length() {
    if i > 0 {
      sb.write_string(",")
    }
    sb.write_string(arr[i].to_string())
  }
  sb.write_string("]")
  sb.to_string()
}

///|
fn json_array_string(arr : Array[String]) -> String {
  let sb = StringBuilder()
  sb.write_string("[")
  for i in 0..<arr.length() {
    if i > 0 {
      sb.write_string(",")
    }
    sb.write_string("\"")
    sb.write_string(escape_json_string(arr[i]))
    sb.write_string("\"")
  }
  sb.write_string("]")
  sb.to_string()
}

///|
fn escape_json_string(s : String) -> String {
  let sb = StringBuilder()
  for c in s.code_units() {
    let ch = c.to_int()
    if ch == 34 { // "
      sb.write_string("\\\"")
    } else if ch == 92 { // \
      sb.write_string("\\\\")
    } else if ch == 10 { // \n
      sb.write_string("\\n")
    } else if ch == 13 { // \r
      sb.write_string("\\r")
    } else if ch == 9 { // \t
      sb.write_string("\\t")
    } else {
      sb.write_char(c.to_int().to_char().unwrap_or('\u0000'))
    }
  }
  sb.to_string()
}

///|
pub fn ClientHello::to_json(self : ClientHello) -> String {
  let sni = match self.server_name {
    Some(s) => "\"\{escape_json_string(s)}\""
    None => "null"
  }
  let sb = StringBuilder()
  sb.write_string("{")
  sb.write_string("\"legacy_version\":\{self.legacy_version.to_int()},")
  sb.write_string("\"record_version\":\{self.record_version.to_int()},")
  sb.write_string("\"cipher_suites\":\{json_array_u16(self.cipher_suites)},")
  sb.write_string(
    "\"compression_methods\":\{json_array_byte(self.compression_methods)},",
  )
  sb.write_string("\"extensions\":\{json_array_u16(self.extensions)},")
  sb.write_string(
    "\"supported_groups\":\{json_array_u16(self.supported_groups)},",
  )
  sb.write_string(
    "\"ec_point_formats\":\{json_array_byte(self.ec_point_formats)},",
  )
  sb.write_string(
    "\"signature_algorithms\":\{json_array_u16(self.signature_algorithms)},",
  )
  sb.write_string(
    "\"alpn_protocols\":\{json_array_string(self.alpn_protocols)},",
  )
  sb.write_string("\"server_name\":\{sni},")
  sb.write_string(
    "\"ja3_string\":\"\{escape_json_string(self.ja3_string())}\",",
  )
  sb.write_string("\"ja3_digest\":\"\{self.ja3_digest()}\",")
  sb.write_string("\"ja4_a\":\"\{self.ja4_a()}\"")
  sb.write_string("}")
  sb.to_string()
}

///|
pub fn ServerHello::to_json(self : ServerHello) -> String {
  let alpn = match self.selected_alpn {
    Some(s) => "\"\{escape_json_string(s)}\""
    None => "null"
  }
  let sb = StringBuilder()
  sb.write_string("{")
  sb.write_string("\"version\":\{self.version.to_int()},")
  sb.write_string("\"cipher_suite\":\{self.cipher_suite.to_int()},")
  sb.write_string("\"compression_method\":\{self.compression_method.to_int()},")
  sb.write_string("\"extensions\":\{json_array_u16(self.extensions)},")
  sb.write_string("\"selected_alpn\":\{alpn},")
  sb.write_string("\"ja4s_a\":\"\{self.ja4s_a()}\"")
  sb.write_string("}")
  sb.to_string()
}

///|
pub fn TlsAlert::to_json(self : TlsAlert) -> String {
  let sb = StringBuilder()
  sb.write_string("{")
  sb.write_string("\"level\":\{self.level.to_int()},")
  sb.write_string("\"level_str\":\"\{self.level_string()}\",")
  sb.write_string("\"description\":\{self.description.to_int()},")
  sb.write_string("\"description_str\":\"\{self.description_string()}\"")
  sb.write_string("}")
  sb.to_string()
}

///|
pub fn TlsCertificate::to_json(self : TlsCertificate) -> String {
  let sb = StringBuilder()
  sb.write_string("{")
  sb.write_string("\"cert_lengths\":\{json_array_int(self.cert_lengths)}")
  sb.write_string("}")
  sb.to_string()
}

///|
pub fn TlsRecord::to_json(self : TlsRecord) -> String {
  match self {
    ClientHelloRecord(ch) => ch.to_json()
    ServerHelloRecord(sh) => sh.to_json()
    AlertRecord(al) => al.to_json()
    CertificateRecord(cert) => cert.to_json()
    GenericRecord(ty, payload) => {
      let ty_str = match ty {
        ChangeCipherSpec => "change_cipher_spec"
        Handshake => "handshake"
        ApplicationData => "application_data"
        Unknown(b) => "unknown_\{b.to_int()}"
      }
      "{\"record_type\":\"\{ty_str}\",\"payload_len\":\{payload.length()}}"
    }
  }
}
