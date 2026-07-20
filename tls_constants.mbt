// TLS Protocol Constants and Specification Reference Database (RFC 8446 / RFC 5246)

///|
/// TLS Record Content Types (RFC 5246 Section 6.2.1)
pub const CONTENT_TYPE_CHANGE_CIPHER_SPEC : Byte = 0x14

///|
pub const CONTENT_TYPE_ALERT : Byte = 0x15

///|
pub const CONTENT_TYPE_HANDSHAKE : Byte = 0x16

///|
pub const CONTENT_TYPE_APPLICATION_DATA : Byte = 0x17

///|
/// Handshake Protocol Message Types (RFC 8446 Section 4)
pub const HANDSHAKE_TYPE_HELLO_REQUEST : Byte = 0

///|
pub const HANDSHAKE_TYPE_CLIENT_HELLO : Byte = 1

///|
pub const HANDSHAKE_TYPE_SERVER_HELLO : Byte = 2

///|
pub const HANDSHAKE_TYPE_HELLO_VERIFY_REQUEST : Byte = 3

///|
pub const HANDSHAKE_TYPE_NEW_SESSION_TICKET : Byte = 4

///|
pub const HANDSHAKE_TYPE_END_OF_EARLY_DATA : Byte = 5

///|
pub const HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS : Byte = 8

///|
pub const HANDSHAKE_TYPE_CERTIFICATE : Byte = 11

///|
pub const HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE : Byte = 12

///|
pub const HANDSHAKE_TYPE_CERTIFICATE_REQUEST : Byte = 13

///|
pub const HANDSHAKE_TYPE_SERVER_HELLO_DONE : Byte = 14

///|
pub const HANDSHAKE_TYPE_CERTIFICATE_VERIFY : Byte = 15

///|
pub const HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE : Byte = 16

///|
pub const HANDSHAKE_TYPE_FINISHED : Byte = 20

///|
pub const HANDSHAKE_TYPE_KEY_UPDATE : Byte = 24

///|
pub const HANDSHAKE_TYPE_MESSAGE_HASH : Byte = 254

///|
/// TLS Protocol Versions (RFC 8446 Section 4.2.1)
pub const VERSION_SSL_3_0 : UInt16 = 0x0300

///|
pub const VERSION_TLS_1_0 : UInt16 = 0x0301

///|
pub const VERSION_TLS_1_1 : UInt16 = 0x0302

///|
pub const VERSION_TLS_1_2 : UInt16 = 0x0303

///|
pub const VERSION_TLS_1_3 : UInt16 = 0x0304

///|
/// Supported Cryptographic Groups (RFC 8446 Section 4.2.7)
pub const GROUP_SECP256R1 : UInt16 = 0x0017 // NIST P-256

///|
pub const GROUP_SECP384R1 : UInt16 = 0x0018 // NIST P-384

///|
pub const GROUP_SECP521R1 : UInt16 = 0x0019 // NIST P-521

///|
pub const GROUP_X25519 : UInt16 = 0x001d // Curve25519

///|
pub const GROUP_X448 : UInt16 = 0x001e // Curve448

///|
pub const GROUP_FFDHE2048 : UInt16 = 0x0100 // Finite Field DH 2048-bit

///|
pub const GROUP_FFDHE3072 : UInt16 = 0x0101 // Finite Field DH 3072-bit

///|
pub const GROUP_FFDHE4096 : UInt16 = 0x0102 // Finite Field DH 4096-bit

///|
/// Signature Schemes (RFC 8446 Section 4.2.3)
pub const SIG_SCHEME_RSA_PKCS1_SHA256 : UInt16 = 0x0401

///|
pub const SIG_SCHEME_RSA_PKCS1_SHA384 : UInt16 = 0x0501

///|
pub const SIG_SCHEME_RSA_PKCS1_SHA512 : UInt16 = 0x0601

///|
pub const SIG_SCHEME_ECDSA_SHA256_NISTP256 : UInt16 = 0x0403

///|
pub const SIG_SCHEME_ECDSA_SHA384_NISTP384 : UInt16 = 0x0503

///|
pub const SIG_SCHEME_ECDSA_SHA512_NISTP521 : UInt16 = 0x0603

///|
pub const SIG_SCHEME_RSA_PSS_RSAE_SHA256 : UInt16 = 0x0804

///|
pub const SIG_SCHEME_RSA_PSS_RSAE_SHA384 : UInt16 = 0x0805

///|
pub const SIG_SCHEME_RSA_PSS_RSAE_SHA512 : UInt16 = 0x0806

///|
pub const SIG_SCHEME_ED25519 : UInt16 = 0x0807

///|
pub const SIG_SCHEME_ED448 : UInt16 = 0x0808

///|
pub fn is_recommended_cipher_id(id : UInt16) -> Bool {
  match id.to_int() {
    // Only TLS 1.3 ciphers and strong TLS 1.2 AEAD ciphers are recommended
    0x1301 | 0x1302 | 0x1303 | 0xc02b | 0xc02c | 0xc02f | 0xc030 => true
    _ => false
  }
}

///|
pub fn is_aead_cipher_id(id : UInt16) -> Bool {
  match id.to_int() {
    // GCM and CCM and CHACHA20-POLY1305 ciphers are AEAD
    0x1301
    | 0x1302
    | 0x1303
    | 0x1304
    | 0x1305
    | 0xc02b
    | 0xc02c
    | 0xc02f
    | 0xc030
    | 0x009c
    | 0x009d
    | 0x00a8
    | 0x00a9
    | 0xcca8
    | 0xcca9
    | 0xccaa => true
    _ => false
  }
}

///|
pub fn is_tls_version_supported(v : UInt16) -> Bool {
  match v {
    VERSION_TLS_1_2 | VERSION_TLS_1_3 => true
    _ => false
  }
}

///|
pub fn is_tls_13_cipher_id(id : UInt16) -> Bool {
  match id.to_int() {
    0x1301 | 0x1302 | 0x1303 | 0x1304 | 0x1305 => true
    _ => false
  }
}

///|
pub fn is_weak_cipher_id(id : UInt16) -> Bool {
  match id.to_int() {
    // NULL, RC4, DES, 3DES ciphers are weak
    0x0001 | 0x0002 | 0x002c | 0x0004 | 0x0005 | 0x000a | 0x0090 => true
    _ => false
  }
}
