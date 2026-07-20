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
  if record_len != 2 {
    return Err(InvalidAlertLength)
  }
  let record_end = 5 + record_len
  if data.length() < record_end {
    return Err(IncompleteRecord(expected=record_end, available=data.length()))
  }

  let level = data[5]
  let description = data[6]

  Ok({ level, description })
}

///|
pub fn TlsAlert::description_string(self : TlsAlert) -> String {
  alert_description_to_string(self.description)
}

///|
pub fn TlsAlert::level_string(self : TlsAlert) -> String {
  alert_level_to_string(self.level)
}
