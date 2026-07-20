// SHA-256 Hashing Algorithm in pure MoonBit

///|
struct Sha256 {
  h : Array[UInt]
  mut len : Int64
  buffer : Array[Byte]
}

///|
fn Sha256::new() -> Sha256 {
  {
    h: [
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
      0x5be0cd19,
    ],
    len: 0,
    buffer: [],
  }
}

///|
let k : Array[UInt] = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
  0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
  0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
  0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
  0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
  0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
  0xc67178f2,
]

///|
fn rotr(val : UInt, bits : Int) -> UInt {
  (val >> bits) | (val << (32 - bits))
}

///|
fn ch(x : UInt, y : UInt, z : UInt) -> UInt {
  (x & y) ^ (x.lnot() & z)
}

///|
fn maj(x : UInt, y : UInt, z : UInt) -> UInt {
  (x & y) ^ (x & z) ^ (y & z)
}

///|
fn big_sigma0(x : UInt) -> UInt {
  rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}

///|
fn big_sigma1(x : UInt) -> UInt {
  rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}

///|
fn small_sigma0(x : UInt) -> UInt {
  rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
}

///|
fn small_sigma1(x : UInt) -> UInt {
  rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
}

///|
fn Sha256::process_block(self : Sha256, block : ArrayView[Byte]) -> Unit {
  let w = Array::new(capacity=64)
  for i in 0..<16 {
    let offset = i * 4
    let val = (block[offset].to_uint() << 24) |
      (block[offset + 1].to_uint() << 16) |
      (block[offset + 2].to_uint() << 8) |
      block[offset + 3].to_uint()
    w.push(val)
  }
  for i in 16..<64 {
    let s0 = small_sigma0(w[i - 15])
    let s1 = small_sigma1(w[i - 2])
    w.push(w[i - 16] + s0 + w[i - 7] + s1)
  }

  let mut a = self.h[0]
  let mut b = self.h[1]
  let mut c = self.h[2]
  let mut d = self.h[3]
  let mut e = self.h[4]
  let mut f = self.h[5]
  let mut g = self.h[6]
  let mut h = self.h[7]

  for i in 0..<64 {
    let t1 = h + big_sigma1(e) + ch(e, f, g) + k[i] + w[i]
    let t2 = big_sigma0(a) + maj(a, b, c)
    h = g
    g = f
    f = e
    e = d + t1
    d = c
    c = b
    b = a
    a = t1 + t2
  }

  self.h[0] = self.h[0] + a
  self.h[1] = self.h[1] + b
  self.h[2] = self.h[2] + c
  self.h[3] = self.h[3] + d
  self.h[4] = self.h[4] + e
  self.h[5] = self.h[5] + f
  self.h[6] = self.h[6] + g
  self.h[7] = self.h[7] + h
}

///|
pub fn Sha256::update(self : Sha256, data : BytesView) -> Unit {
  self.len = self.len + data.length().to_int64()
  let mut offset = 0
  let len = data.length()
  while offset < len {
    self.buffer.push(data[offset])
    offset = offset + 1
    if self.buffer.length() == 64 {
      self.process_block(self.buffer[:])
      self.buffer.clear()
    }
  }
}

///|
pub fn Sha256::finalize(self : Sha256) -> Bytes {
  let total_bits = self.len * 8
  self.buffer.push(0x80)
  while self.buffer.length() % 64 != 56 {
    self.buffer.push(0x00)
  }

  // Append bit length in big-endian
  for i in 0..<8 {
    let shift = (7 - i) * 8
    let b = ((total_bits >> shift) & 0xff).to_byte()
    self.buffer.push(b)
  }

  self.process_block(self.buffer[0:64])
  if self.buffer.length() > 64 {
    self.process_block(self.buffer[64:])
  }

  let out = Array::new(capacity=32)
  for i in 0..<8 {
    let val = self.h[i]
    out.push(((val >> 24) & 0xff).to_byte())
    out.push(((val >> 16) & 0xff).to_byte())
    out.push(((val >> 8) & 0xff).to_byte())
    out.push((val & 0xff).to_byte())
  }
  Bytes::from_array(out)
}

///|
pub fn sha256_hash(data : BytesView) -> Bytes {
  let s = Sha256::new()
  s.update(data)
  s.finalize()
}

///|
pub fn sha256_hex(data : BytesView) -> String {
  let hash = sha256_hash(data)
  let sb = StringBuilder()
  for b in hash {
    let s = b.to_int().to_string(radix=16)
    if s.length() == 1 {
      sb.write_string("0")
    }
    sb.write_string(s)
  }
  sb.to_string()
}
