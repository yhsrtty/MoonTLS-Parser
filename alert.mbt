///|
pub fn parse_alert(data : BytesView) -> Result[TlsAlert, ParseError] {
  if data.length() < 5 {
    return Err(IncompleteRecord(expected=5, available=data.length()))
  }
  if data[0].to_int() != 0x15 {
    return Err(NotTlsHandshake) // Reuse or we can check record type
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
  if record_len != 2 {
    return Err(InvalidAlertLength)
  }

  let level = data[5]
  let description = data[6]

  Ok({ level, description })
}

///|
pub fn TlsAlert::description_string(self : TlsAlert) -> String {
  match self.description.to_int() {
    0 => "close_notify"
    10 => "unexpected_message"
    20 => "bad_record_mac"
    30 => "decompression_failure"
    40 => "handshake_failure"
    41 => "no_certificate"
    42 => "bad_certificate"
    43 => "unsupported_certificate"
    44 => "certificate_revoked"
    45 => "certificate_expired"
    46 => "certificate_unknown"
    47 => "illegal_parameter"
    48 => "unknown_ca"
    49 => "access_denied"
    50 => "decode_error"
    51 => "decrypt_error"
    60 => "export_restriction"
    70 => "protocol_version"
    71 => "insufficient_security"
    80 => "internal_error"
    86 => "inappropriate_fallback"
    90 => "user_canceled"
    100 => "no_renegotiation"
    110 => "unsupported_extension"
    111 => "certificate_unobtainable"
    112 => "unrecognized_name"
    113 => "bad_certificate_status_response"
    114 => "bad_certificate_hash_value"
    115 => "unknown_psk_identity"
    116 => "certificate_required"
    120 => "no_application_protocol"
    _ => "unknown_alert_\{self.description.to_int()}"
  }
}

///|
pub fn TlsAlert::level_string(self : TlsAlert) -> String {
  match self.level.to_int() {
    1 => "warning"
    2 => "fatal"
    _ => "unknown_level_\{self.level.to_int()}"
  }
}
