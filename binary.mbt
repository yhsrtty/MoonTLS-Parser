///|
fn has_range(data : BytesView, offset : Int, len : Int) -> Bool {
  offset >= 0 &&
  len >= 0 &&
  offset <= data.length() &&
  len <= data.length() - offset
}

///|
fn read_u8(data : BytesView, offset : Int) -> Int? {
  if has_range(data, offset, 1) {
    Some(data[offset].to_int())
  } else {
    None
  }
}

///|
fn read_u16_int(data : BytesView, offset : Int) -> Int? {
  if has_range(data, offset, 2) {
    Some(data[offset].to_int() * 256 + data[offset + 1].to_int())
  } else {
    None
  }
}

///|
fn read_u24_int(data : BytesView, offset : Int) -> Int? {
  if has_range(data, offset, 3) {
    Some(
      data[offset].to_int() * 65536 +
      data[offset + 1].to_int() * 256 +
      data[offset + 2].to_int(),
    )
  } else {
    None
  }
}

///|
fn read_u16(data : BytesView, offset : Int) -> UInt16? {
  match read_u16_int(data, offset) {
    Some(v) => Some(v.to_uint16())
    None => None
  }
}

///|
fn require_range(
  data : BytesView,
  offset : Int,
  len : Int,
  field : String,
) -> Result[Unit, ParseError] {
  if has_range(data, offset, len) {
    Ok(())
  } else {
    Err(BadLength(field~, offset~))
  }
}

///|
fn bytes_to_ascii(data : BytesView, offset : Int, len : Int) -> String? {
  if !has_range(data, offset, len) {
    None
  } else {
    let out : Array[Char] = []
    for i in 0..<len {
      let b = data[offset + i].to_int()
      if b < 32 || b > 126 {
        return None
      }
      match b.to_char() {
        Some(c) => out.push(c)
        None => return None
      }
    }
    Some(String::from_array(out))
  }
}

///|
fn is_grease(v : UInt16) -> Bool {
  let n = v.to_int()
  let hi = n / 256
  let lo = n % 256
  hi == lo && hi % 16 == 10
}

///|
pub fn uint16_to_hex4(value : UInt16) -> String {
  value.to_string(radix=16).pad_start(4, '0')
}
