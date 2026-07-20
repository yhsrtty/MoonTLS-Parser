// TLS Alert Description to RFC standard name formatter

///|
pub fn alert_description_to_string(desc : Byte) -> String {
  match desc.to_int() {
    0 => "close_notify"
    10 => "unexpected_message"
    20 => "bad_record_mac"
    21 => "decryption_failed_RESERVED"
    22 => "record_overflow"
    30 => "decompression_failure"
    40 => "handshake_failure"
    41 => "no_certificate_RESERVED"
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
    60 => "export_restriction_RESERVED"
    70 => "protocol_version"
    71 => "insufficient_security"
    80 => "internal_error"
    86 => "inappropriate_fallback"
    90 => "user_canceled"
    100 => "no_renegotiation"
    109 => "missing_extension"
    110 => "unsupported_extension"
    111 => "certificate_unobtainable"
    112 => "unrecognized_name"
    113 => "bad_certificate_status_response"
    114 => "bad_certificate_hash_value"
    115 => "unknown_psk_identity"
    116 => "certificate_required"
    120 => "no_application_protocol"
    _ =>
      "unknown_alert_description (0x" + desc.to_int().to_string(radix=16) + ")"
  }
}

///|
pub fn alert_level_to_string(level : Byte) -> String {
  match level.to_int() {
    1 => "warning"
    2 => "fatal"
    _ => "unknown_level"
  }
}
