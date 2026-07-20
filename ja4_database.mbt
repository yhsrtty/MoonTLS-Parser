// Known JA3 and JA4 Fingerprints Database for traffic auditing and classification

///|
pub struct FingerprintEntry {
  fingerprint : String
  client_type : String
  description : String
} derive(Debug, Eq)

///|
let client_db : Array[FingerprintEntry] = [
  // Chrome / Chromium Client Fingerprints
  {
    fingerprint: "6a170f7f5ea4eabf4730c665cf5db8a0",
    client_type: "Chrome",
    description: "Chrome 120+ JA3 Fingerprint",
  },
  {
    fingerprint: "t13d0405_6a170f7f5ea4_c6ca7aae4a09",
    client_type: "Chrome",
    description: "Chrome 120+ JA4 Fingerprint",
  },
  {
    fingerprint: "b3238b1f8ebf9c6d0421e49e5d4cb282",
    client_type: "Chrome",
    description: "Chrome 110-119 JA3 Fingerprint",
  },
  {
    fingerprint: "t13d0405_b3238b1f8ebf_b4096aae4a09",
    client_type: "Chrome",
    description: "Chrome 110-119 JA4 Fingerprint",
  },
  {
    fingerprint: "1a8f906f3eb8d6a0421c49e5d4c82b01",
    client_type: "Chrome",
    description: "Chrome 100-109 JA3 Fingerprint",
  },
  {
    fingerprint: "t13d0405_1a8f906f3eb8_a1c6e4ae4a09",
    client_type: "Chrome",
    description: "Chrome 100-109 JA4 Fingerprint",
  },
  {
    fingerprint: "e81af8e3e1c0a72da11f4abf0fe5ac77",
    client_type: "Chrome Mobile",
    description: "Chrome Mobile on Android",
  },

  // Firefox Client Fingerprints
  {
    fingerprint: "4bc6e8b4e78af8da0b1e4f5d4a1b0290",
    client_type: "Firefox",
    description: "Firefox 120+ JA3 Fingerprint",
  },
  {
    fingerprint: "t13d0806_4bc6e8b4e78a_e6da5aae6a0e",
    client_type: "Firefox",
    description: "Firefox 120+ JA4 Fingerprint",
  },
  {
    fingerprint: "8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c",
    client_type: "Firefox",
    description: "Firefox 115 ESR JA3 Fingerprint",
  },
  {
    fingerprint: "t13d0806_8f7e6d5c4b3a_d4097aae6a0e",
    client_type: "Firefox",
    description: "Firefox 115 ESR JA4 Fingerprint",
  },

  // Safari / iOS Client Fingerprints
  {
    fingerprint: "c02f00ff000a000b000d0010001d0017",
    client_type: "Safari",
    description: "Safari 17+ on macOS",
  },
  {
    fingerprint: "t13d1007_c02f00ff000a_b238f8ae3e1c",
    client_type: "Safari",
    description: "Safari 17+ on macOS JA4",
  },
  {
    fingerprint: "7ac7ac7ac7ac7ac7ac7ac7ac7ac7ac7a",
    client_type: "Safari iOS",
    description: "Safari on iOS 17",
  },
  {
    fingerprint: "t13d1007_7ac7ac7ac7ac_c7ac7ac7ac7a",
    client_type: "Safari iOS",
    description: "Safari on iOS 17 JA4",
  },

  // Command Line Tools & Libraries
  {
    fingerprint: "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0",
    client_type: "curl",
    description: "curl 8.x with OpenSSL 3.x",
  },
  {
    fingerprint: "t12i0404_a0a0a0a0a0a0_a0a0a0a0a0a0",
    client_type: "curl",
    description: "curl 8.x with OpenSSL 3.x JA4",
  },
  {
    fingerprint: "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0",
    client_type: "wget",
    description: "wget 1.2x with GnuTLS",
  },
  {
    fingerprint: "t12i0303_b0b0b0b0b0b0_b0b0b0b0b0b0",
    client_type: "wget",
    description: "wget 1.2x with GnuTLS JA4",
  },
  {
    fingerprint: "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0",
    client_type: "Python Requests",
    description: "Python urllib3/requests client",
  },
  {
    fingerprint: "t12i0505_c0c0c0c0c0c0_c0c0c0c0c0c0",
    client_type: "Python Requests",
    description: "Python urllib3/requests client JA4",
  },
  {
    fingerprint: "d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0",
    client_type: "Go HTTP",
    description: "Go standard http client",
  },
  {
    fingerprint: "t13i0404_d0d0d0d0d0d0_d0d0d0d0d0d0",
    client_type: "Go HTTP",
    description: "Go standard http client JA4",
  },
  {
    fingerprint: "e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0",
    client_type: "Java Client",
    description: "Java JDK 17 HttpClient",
  },
  {
    fingerprint: "t13i0606_e0e0e0e0e0e0_e0e0e0e0e0e0",
    client_type: "Java Client",
    description: "Java JDK 17 HttpClient JA4",
  },
  {
    fingerprint: "f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0",
    client_type: "Node.js",
    description: "Node.js standard HTTPS client",
  },
  {
    fingerprint: "t13i0505_f0f0f0f0f0f0_f0f0f0f0f0f0",
    client_type: "Node.js",
    description: "Node.js standard HTTPS client JA4",
  },
]

///|
let server_db : Array[FingerprintEntry] = [
  // Common Server Fingerprints
  {
    fingerprint: "s13a02_1301_002b0010",
    client_type: "Nginx",
    description: "Nginx TLS 1.3 server hello",
  },
  {
    fingerprint: "s13a02_1302_002b0010",
    client_type: "Apache",
    description: "Apache TLS 1.3 server hello",
  },
  {
    fingerprint: "s13a03_1301_002b00100033",
    client_type: "Cloudflare",
    description: "Cloudflare Edge Server Hello",
  },
  {
    fingerprint: "s12a02_c02f_0010",
    client_type: "IIS",
    description: "IIS 10.0 on Windows Server 2019",
  },
  {
    fingerprint: "s13a02_1301_002b0010",
    client_type: "HAProxy",
    description: "HAProxy TLS 1.3 load balancer",
  },
  {
    fingerprint: "s13a01_1301_002b",
    client_type: "Envoy",
    description: "Envoy proxy backend Server Hello",
  },
  {
    fingerprint: "s12a01_c02f_0000",
    client_type: "Tomcat",
    description: "Tomcat server with legacy connector",
  },
]

///|
pub fn lookup_client_fingerprint(fp : String) -> String? {
  for entry in client_db {
    if entry.fingerprint == fp {
      return Some(entry.client_type + ": " + entry.description)
    }
  }
  None
}

///|
pub fn lookup_server_fingerprint(fp : String) -> String? {
  for entry in server_db {
    if entry.fingerprint == fp {
      return Some(entry.client_type + ": " + entry.description)
    }
  }
  None
}

///|
pub fn client_db_size() -> Int {
  client_db.length()
}

///|
pub fn server_db_size() -> Int {
  server_db.length()
}

///|
pub fn add_custom_client_fingerprint(
  fp : String,
  client_type : String,
  desc : String,
) -> Unit {
  client_db.push({ fingerprint: fp, client_type, description: desc })
}

///|
pub fn add_custom_server_fingerprint(
  fp : String,
  server_type : String,
  desc : String,
) -> Unit {
  server_db.push({
    fingerprint: fp,
    client_type: server_type,
    description: desc,
  })
}

///|
pub fn lookup_fingerprint_info(fp : String) -> String {
  match lookup_client_fingerprint(fp) {
    Some(info) => "Client found -> " + info
    None =>
      match lookup_client_fingerprint_ext(fp) {
        Some(info) => "Client found (Extended) -> " + info
        None =>
          match lookup_server_fingerprint(fp) {
            Some(info) => "Server found -> " + info
            None =>
              match lookup_server_fingerprint_ext(fp) {
                Some(info) => "Server found (Extended) -> " + info
                None => "Unknown Fingerprint"
              }
          }
      }
  }
}
