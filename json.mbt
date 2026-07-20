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
    ClientKeyExchangeRecord(cke) =>
      "{\"record_type\":\"client_key_exchange\",\"payload_len\":\{cke.raw.length()}}"
    ServerKeyExchangeRecord(ske) =>
      "{\"record_type\":\"server_key_exchange\",\"payload_len\":\{ske.raw.length()}}"
    NewSessionTicketRecord(nst) => {
      let lifetime = nst.lifetime.reinterpret_as_int()
      let ticket_len = nst.ticket.length()
      "{\"record_type\":\"new_session_ticket\",\"lifetime\":\{lifetime},\"ticket_len\":\{ticket_len}}"
    }
    EncryptedExtensionsRecord(ee) => {
      let ext_arr = json_array_u16(ee.extensions)
      "{\"record_type\":\"encrypted_extensions\",\"extensions\":\{ext_arr}}"
    }
    HelloRequestRecord(_) => "{\"record_type\":\"hello_request\"}"
    HelloVerifyRequestRecord(hvr) => {
      let ver = hvr.version.to_int()
      let cookie_len = hvr.cookie.length()
      "{\"record_type\":\"hello_verify_request\",\"version\":\{ver},\"cookie_len\":\{cookie_len}}"
    }
    CertificateRequestRecord(cr) => {
      let types = cr.certificate_types.map(fn(b) { b.to_int() })
      let types_arr = json_array_int(types)
      let algs_arr = json_array_u16(cr.supported_signature_algorithms)
      "{\"record_type\":\"certificate_request\",\"certificate_types\":\{types_arr},\"supported_signature_algorithms\":\{algs_arr}}"
    }
    CertificateVerifyRecord(cv) => {
      let alg = cv.signature_algorithm.to_int()
      let sig_len = cv.signature.length()
      "{\"record_type\":\"certificate_verify\",\"signature_algorithm\":\{alg},\"signature_len\":\{sig_len}}"
    }
    FinishedRecord(fn_) =>
      "{\"record_type\":\"finished\",\"verify_data_len\":\{fn_.verify_data.length()}}"
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
