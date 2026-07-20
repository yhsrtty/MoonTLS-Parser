// TLS Cipher Suite ID to standard standard name formatter

///|
pub fn cipher_suite_id_to_string(id : UInt16) -> String {
  match id.to_int() {
    // TLS 1.3 Cipher Suites
    0x1301 => "TLS_AES_128_GCM_SHA256"
    0x1302 => "TLS_AES_256_GCM_SHA384"
    0x1303 => "TLS_CHACHA20_POLY1305_SHA256"
    0x1304 => "TLS_AES_128_CCM_SHA256"
    0x1305 => "TLS_AES_128_CCM_8_SHA256"

    // ECDHE ECDSA Cipher Suites (TLS 1.2)
    0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
    0xc02c => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
    0xc023 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
    0xc024 => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"
    0xc009 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
    0xc00a => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"

    // ECDHE RSA Cipher Suites (TLS 1.2)
    0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    0xc027 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
    0xc028 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
    0xc013 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
    0xc014 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"

    // DHE DSS/RSA Cipher Suites
    0x0033 => "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
    0x0039 => "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"
    0x0035 => "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
    0x002f => "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
    0x0032 => "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"
    0x0038 => "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"

    // Legacy RSA Cipher Suites
    0x009c => "TLS_RSA_WITH_AES_128_GCM_SHA256"
    0x009d => "TLS_RSA_WITH_AES_256_GCM_SHA384"
    0x003c => "TLS_RSA_WITH_AES_128_CBC_SHA256"
    0x003d => "TLS_RSA_WITH_AES_256_CBC_SHA256"
    0x000a => "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
    0x002c => "TLS_RSA_WITH_NULL_SHA256"
    0x0002 => "TLS_RSA_WITH_NULL_SHA"
    0x0001 => "TLS_RSA_WITH_NULL_MD5"

    // PSK Cipher Suites
    0x008c => "TLS_PSK_WITH_AES_128_CBC_SHA"
    0x008d => "TLS_PSK_WITH_AES_256_CBC_SHA"
    0x0090 => "TLS_PSK_WITH_3DES_EDE_CBC_SHA"
    0x00a8 => "TLS_PSK_WITH_AES_128_GCM_SHA256"
    0x00a9 => "TLS_PSK_WITH_AES_256_GCM_SHA384"

    // ECDH Cipher Suites
    0xc004 => "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"
    0xc005 => "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"
    0xc00e => "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"
    0xc00f => "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA"

    // Camellia / SEED Cipher Suites
    0x0041 => "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"
    0x0084 => "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"
    0x0096 => "TLS_RSA_WITH_SEED_CBC_SHA"

    // CHACHA20 POLY1305 Legacy
    0xcca8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
    0xcca9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
    0xccaa => "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
    _ =>
      if is_grease(id) {
        "grease_cipher (0x" + id.to_int().to_string(radix=16) + ")"
      } else {
        "unknown_cipher (0x" + id.to_int().to_string(radix=16) + ")"
      }
  }
}

///|
pub fn TlsRecord::cipher_summary(self : TlsRecord) -> String {
  match self {
    ClientHelloRecord(hello) => {
      let list = []
      for c in hello.cipher_suites {
        list.push(cipher_suite_id_to_string(c))
      }
      "Client offers ciphers: [" + list.join(", ") + "]"
    }
    ServerHelloRecord(hello) =>
      "Server selected cipher: " + cipher_suite_id_to_string(hello.cipher_suite)
    _ => "No cipher negotiated"
  }
}
