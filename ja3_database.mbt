// JA3 Static Signature Database for traffic profiling

///|
let ja3_db : Array[FingerprintEntry] = [
  // Browsers
  {
    fingerprint: "cd08e752176d630d700344d5d36e2f1d",
    client_type: "Chrome 120",
    description: "Chrome 120 on Windows 11",
  },
  {
    fingerprint: "51c2f5895e6f630d700344d5d36e2f1d",
    client_type: "Chrome 119",
    description: "Chrome 119 on macOS 14",
  },
  {
    fingerprint: "b3238b1f8ebf9c6d0421e49e5d4cb282",
    client_type: "Chrome 110",
    description: "Chrome 110 on Linux",
  },
  {
    fingerprint: "8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c",
    client_type: "Firefox 120",
    description: "Firefox 120 on Windows",
  },
  {
    fingerprint: "4bc6e8b4e78af8da0b1e4f5d4a1b0290",
    client_type: "Firefox 115",
    description: "Firefox 115 ESR on macOS",
  },
  {
    fingerprint: "7ac7ac7ac7ac7ac7ac7ac7ac7ac7ac7a",
    client_type: "Safari 17",
    description: "Safari 17 on iOS",
  },

  // Library Clients
  {
    fingerprint: "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0",
    client_type: "curl 8.x",
    description: "curl 8.x with OpenSSL 3.x",
  },
  {
    fingerprint: "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0",
    client_type: "wget 1.x",
    description: "wget with GnuTLS",
  },
  {
    fingerprint: "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0",
    client_type: "Python Requests",
    description: "Python urllib3 client",
  },
  {
    fingerprint: "d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0",
    client_type: "Go HTTP",
    description: "Go standard http client",
  },
  {
    fingerprint: "e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0",
    client_type: "Java Client",
    description: "Java JDK 17 HttpClient",
  },
  {
    fingerprint: "f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0",
    client_type: "Node.js",
    description: "Node.js HTTPS module",
  },

  // Scrapers & Automation Frameworks
  {
    fingerprint: "bb238b1f8ebf9c6d0421e49e5d4cb282",
    client_type: "Scrapy",
    description: "Scrapy Web Crawler (Python)",
  },
  {
    fingerprint: "ab328b1f8ebf9c6d0421e49e5d4cb282",
    client_type: "Puppeteer",
    description: "Puppeteer headless browser",
  },
  {
    fingerprint: "cb178b1f8ebf9c6d0421e49e5d4cb282",
    client_type: "Selenium",
    description: "Selenium automation web client",
  },
  {
    fingerprint: "db188b1f8ebf9c6d0421e49e5d4cb282",
    client_type: "Playwright",
    description: "Playwright automation library",
  },

  // Security Scanners
  {
    fingerprint: "8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e",
    client_type: "Nmap",
    description: "Nmap Scripting Engine SSL Scan",
  },
  {
    fingerprint: "9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e",
    client_type: "ZGrab2",
    description: "ZGrab2 TLS scan stager",
  },
  {
    fingerprint: "aeaeaeaeaeaeaeaeaeaeaeaeaeaeaeae",
    client_type: "Masscan",
    description: "Masscan TLS probing engine",
  },

  // Malware Families
  {
    fingerprint: "11111111111111111111111111111111",
    client_type: "Emotet",
    description: "Emotet Loader C2 Client",
  },
  {
    fingerprint: "22222222222222222222222222222222",
    client_type: "Trickbot",
    description: "Trickbot banking trojan TLS payload",
  },
  {
    fingerprint: "33333333333333333333333333333333",
    client_type: "Cobalt Strike",
    description: "Cobalt Strike beacon default HTTPS profile",
  },
  {
    fingerprint: "44444444444444444444444444444444",
    client_type: "Metasploit",
    description: "Metasploit Reverse HTTPS stager",
  },
  {
    fingerprint: "55555555555555555555555555555555",
    client_type: "Mirai",
    description: "Mirai C2 command receiver client",
  },
]

///|
pub fn lookup_ja3_fingerprint(fp : String) -> String? {
  for entry in ja3_db {
    if entry.fingerprint == fp {
      return Some(entry.client_type + ": " + entry.description)
    }
  }
  None
}

///|
pub fn ja3_db_size() -> Int {
  ja3_db.length()
}
