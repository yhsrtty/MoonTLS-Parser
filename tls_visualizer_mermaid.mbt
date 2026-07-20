// Mermaid Sequence Diagram Generator for TLS Handshake Flows

///|
pub fn generate_mermaid_diagram(
  records : Array[TlsRecord],
  directions : Array[Bool],
) -> String {
  let sb = StringBuilder()
  sb.write_string("```mermaid\n")
  sb.write_string("sequenceDiagram\n")
  sb.write_string("  autonumber\n")
  sb.write_string("  actor Client as Client Browser\n")
  sb.write_string("  actor Server as Remote Server\n")

  let len = Int::min(records.length(), directions.length())
  for i in 0..<len {
    let rec = records[i]
    let dir = directions[i]
    match rec {
      ClientHelloRecord(hello) => {
        sb.write_string("  Client->>Server: ClientHello (TLS 1.2/1.3)\n")
        let sni = hello.server_name.unwrap_or("-")
        sb.write_string(
          "  Note over Client,Server: SNI: \{sni} | ALPN: [\{hello.alpn_protocols.join(",")}]\n",
        )
      }
      ServerHelloRecord(hello) => {
        sb.write_string("  Server->>Client: ServerHello\n")
        let alpn = hello.selected_alpn.unwrap_or("-")
        let cipher = uint16_to_hex4(hello.cipher_suite)
        sb.write_string(
          "  Note over Client,Server: Selected ALPN: \{alpn} | Cipher: \{cipher}\n",
        )
      }
      AlertRecord(alert) => {
        let level = alert.level_string()
        let desc = alert.description_string()
        if dir {
          sb.write_string("  Client->>Server: Alert (\{level}: \{desc})\n")
        } else {
          sb.write_string("  Server->>Client: Alert (\{level}: \{desc})\n")
        }
      }
      CertificateRecord(cert) => {
        let count = cert.cert_lengths.length()
        sb.write_string(
          "  Server->>Client: Certificate Chain (\{count} certs)\n",
        )
      }
      ClientKeyExchangeRecord(_) =>
        sb.write_string("  Client->>Server: ClientKeyExchange\n")
      ServerKeyExchangeRecord(_) =>
        sb.write_string("  Server->>Client: ServerKeyExchange\n")
      NewSessionTicketRecord(nst) => {
        let life = nst.lifetime.reinterpret_as_int()
        sb.write_string(
          "  Server->>Client: NewSessionTicket (lifetime: \{life}s)\n",
        )
      }
      EncryptedExtensionsRecord(_) =>
        sb.write_string("  Server->>Client: EncryptedExtensions\n")
      HelloRequestRecord(_) =>
        sb.write_string("  Server->>Client: HelloRequest\n")
      HelloVerifyRequestRecord(_) =>
        sb.write_string("  Server->>Client: HelloVerifyRequest\n")
      CertificateRequestRecord(_) =>
        sb.write_string("  Server->>Client: CertificateRequest\n")
      CertificateVerifyRecord(_) =>
        sb.write_string("  Client->>Server: CertificateVerify\n")
      FinishedRecord(_) =>
        if dir {
          sb.write_string("  Client->>Server: Finished\n")
        } else {
          sb.write_string("  Server->>Client: Finished\n")
        }
      GenericRecord(ty, _) => {
        let ty_str = match ty {
          ChangeCipherSpec => "ChangeCipherSpec"
          Handshake => "Handshake (Generic)"
          ApplicationData => "ApplicationData"
          Unknown(b) => "Unknown (0x" + b.to_int().to_string(radix=16) + ")"
        }
        if dir {
          sb.write_string("  Client->>Server: \{ty_str}\n")
        } else {
          sb.write_string("  Server->>Client: \{ty_str}\n")
        }
      }
    }
  }
  sb.write_string("```\n")
  sb.to_string()
}
