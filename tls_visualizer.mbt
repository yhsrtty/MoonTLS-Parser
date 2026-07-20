// TLS Handshake Sequence Diagram and Flow Visualizer

///|
pub struct HandshakeEvent {
  direction_is_client_to_server : Bool
  label : String
  details : Array[String]
} derive(Debug, Eq)

///|
pub fn generate_sequence_diagram(events : Array[HandshakeEvent]) -> String {
  let sb = StringBuilder()
  sb.write_string("\n")
  sb.write_string(
    "       Client                                              Server\n",
  )
  sb.write_string(
    "         |                                                   |\n",
  )

  for e in events {
    if e.direction_is_client_to_server {
      // Client to Server Arrow
      sb.write_string(
        "         |                                                   |\n",
      )
      let label_padded = e.label.pad_end(45, '-')
      sb.write_string("         |---------- \{label_padded}--->|\n")
      for detail in e.details {
        let detail_padded = detail.pad_end(45, ' ')
        sb.write_string("         |           \{detail_padded}   |\n")
      }
      sb.write_string(
        "         |                                                   |\n",
      )
    } else {
      // Server to Client Arrow
      sb.write_string(
        "         |                                                   |\n",
      )
      let label_padded = e.label.pad_start(45, '-')
      sb.write_string("         |<--------- \{label_padded}----|\n")
      for detail in e.details {
        let detail_padded = detail.pad_start(45, ' ')
        sb.write_string("         |           \{detail_padded}   |\n")
      }
      sb.write_string(
        "         |                                                   |\n",
      )
    }
  }
  sb.write_string(
    "         |                                                   |\n",
  )
  sb.write_string("       [End of TLS Handshake Observation]\n")
  sb.to_string()
}

///|
pub fn TlsRecord::to_event(
  self : TlsRecord,
  from_client : Bool,
) -> HandshakeEvent {
  match self {
    ClientHelloRecord(hello) => {
      let details = [
        "SNI: " + hello.server_name.unwrap_or("-"),
        "ALPN: " + hello.alpn_protocols.join(","),
        "JA4: " + hello.ja4(),
      ]
      {
        direction_is_client_to_server: from_client,
        label: "ClientHello",
        details,
      }
    }
    ServerHelloRecord(hello) => {
      let details = [
        "Ver: " + hello.version.to_int().to_string(radix=16),
        "Cipher: " + uint16_to_hex4(hello.cipher_suite),
        "ALPN: " + hello.selected_alpn.unwrap_or("-"),
        "JA4S: " + hello.ja4s(),
      ]
      {
        direction_is_client_to_server: from_client,
        label: "ServerHello",
        details,
      }
    }
    AlertRecord(alert) => {
      let details = [
        "Level: " + alert.level_string(),
        "Desc: " + alert.description_string(),
      ]
      {
        direction_is_client_to_server: from_client,
        label: "Alert (" + alert.level_string() + ")",
        details,
      }
    }
    CertificateRecord(cert) => {
      let count = cert.cert_lengths.length()
      let details = [
        "Chain Count: " + count.to_string(),
        "Lengths: " + cert.cert_lengths.map(fn(l) { l.to_string() }).join(","),
      ]
      {
        direction_is_client_to_server: from_client,
        label: "Certificate",
        details,
      }
    }
    ClientKeyExchangeRecord(_) =>
      {
        direction_is_client_to_server: from_client,
        label: "ClientKeyExchange",
        details: [],
      }
    ServerKeyExchangeRecord(_) =>
      {
        direction_is_client_to_server: from_client,
        label: "ServerKeyExchange",
        details: [],
      }
    NewSessionTicketRecord(nst) => {
      let details = [
        "Lifetime: " + nst.lifetime.reinterpret_as_int().to_string() + "s",
        "Ticket Len: " + nst.ticket.length().to_string(),
      ]
      {
        direction_is_client_to_server: from_client,
        label: "NewSessionTicket",
        details,
      }
    }
    EncryptedExtensionsRecord(ee) => {
      let details = [
        "Extensions: " +
        ee.extensions.map(fn(e) { uint16_to_hex4(e) }).join(","),
      ]
      {
        direction_is_client_to_server: from_client,
        label: "EncryptedExtensions",
        details,
      }
    }
    HelloRequestRecord(_) =>
      {
        direction_is_client_to_server: from_client,
        label: "HelloRequest",
        details: [],
      }
    HelloVerifyRequestRecord(hvr) => {
      let details = [
        "Ver: " + uint16_to_hex4(hvr.version),
        "Cookie Len: " + hvr.cookie.length().to_string(),
      ]
      {
        direction_is_client_to_server: from_client,
        label: "HelloVerifyRequest",
        details,
      }
    }
    CertificateRequestRecord(cr) => {
      let details = [
        "Types: " +
        cr.certificate_types.map(fn(t) { t.to_int().to_string() }).join(","),
        "Algs: " +
        cr.supported_signature_algorithms
        .map(fn(a) { uint16_to_hex4(a) })
        .join(","),
      ]
      {
        direction_is_client_to_server: from_client,
        label: "CertificateRequest",
        details,
      }
    }
    CertificateVerifyRecord(cv) => {
      let details = [
        "Alg: " + uint16_to_hex4(cv.signature_algorithm),
        "Sig Len: " + cv.signature.length().to_string(),
      ]
      {
        direction_is_client_to_server: from_client,
        label: "CertificateVerify",
        details,
      }
    }
    FinishedRecord(fn_) => {
      let details = ["Verify Data Len: " + fn_.verify_data.length().to_string()]
      { direction_is_client_to_server: from_client, label: "Finished", details }
    }
    GenericRecord(ty, payload) => {
      let ty_str = match ty {
        ChangeCipherSpec => "ChangeCipherSpec"
        Handshake => "Handshake (Generic)"
        ApplicationData => "ApplicationData"
        Unknown(b) => "Unknown (0x" + b.to_int().to_string(radix=16) + ")"
      }
      let details = ["Length: " + payload.length().to_string()]
      { direction_is_client_to_server: from_client, label: ty_str, details }
    }
  }
}

///|
pub fn visualize_handshake(
  records : Array[TlsRecord],
  directions : Array[Bool],
) -> String {
  let events = []
  let len = Int::min(records.length(), directions.length())
  for i in 0..<len {
    events.push(records[i].to_event(directions[i]))
  }
  generate_sequence_diagram(events)
}
