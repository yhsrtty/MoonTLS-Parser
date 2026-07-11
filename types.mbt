///|
pub enum ParseError {
  NotTlsHandshake
  IncompleteRecord(expected~ : Int, available~ : Int)
  BadHandshakeType(Int)
  BadLength(field~ : String, offset~ : Int)
  UnsupportedRecordVersion(UInt16)
} derive(Debug, Eq)

///|
pub struct ClientHello {
  legacy_version : UInt16
  record_version : UInt16
  cipher_suites : Array[UInt16]
  compression_methods : Array[Byte]
  extensions : Array[UInt16]
  supported_groups : Array[UInt16]
  ec_point_formats : Array[Byte]
  signature_algorithms : Array[UInt16]
  alpn_protocols : Array[String]
  server_name : String?
  raw_length : Int
} derive(Debug)

///|
pub enum StreamResult {
  NeedMore
  Parsed(ClientHello)
  Rejected(ParseError)
} derive(Debug)

///|
pub struct ClientHelloStream {
  buffer : Array[Byte]
} derive(Debug)

///|
pub fn ClientHelloStream::new() -> ClientHelloStream {
  { buffer: [] }
}

///|
pub fn ClientHelloStream::reset(self : ClientHelloStream) -> Unit {
  self.buffer.clear()
}
