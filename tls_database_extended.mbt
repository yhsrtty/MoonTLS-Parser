// Extended Known JA3/JA4 Fingerprints Database for advanced profiling

///|
let client_db_ext : Array[FingerprintEntry] = [
  // Chrome Version History
  {
    fingerprint: "chrome_119_ja3",
    client_type: "Chrome 119",
    description: "Chrome 119 on Windows 11",
  },
  {
    fingerprint: "chrome_118_ja3",
    client_type: "Chrome 118",
    description: "Chrome 118 on macOS 14",
  },
  {
    fingerprint: "chrome_117_ja3",
    client_type: "Chrome 117",
    description: "Chrome 117 on Linux Ubuntu",
  },
  {
    fingerprint: "chrome_116_ja3",
    client_type: "Chrome 116",
    description: "Chrome 116 on ChromeOS",
  },
  {
    fingerprint: "chrome_115_ja3",
    client_type: "Chrome 115",
    description: "Chrome 115 on Windows 10",
  },
  {
    fingerprint: "chrome_114_ja3",
    client_type: "Chrome 114",
    description: "Chrome 114 on macOS 13",
  },
  {
    fingerprint: "chrome_113_ja3",
    client_type: "Chrome 113",
    description: "Chrome 113 on Android 13",
  },
  {
    fingerprint: "chrome_112_ja3",
    client_type: "Chrome 112",
    description: "Chrome 112 on iOS 16",
  },
  {
    fingerprint: "chrome_111_ja3",
    client_type: "Chrome 111",
    description: "Chrome 111 on Windows Server",
  },
  {
    fingerprint: "chrome_110_ja3",
    client_type: "Chrome 110",
    description: "Chrome 110 on Linux Fedora",
  },
  {
    fingerprint: "chrome_109_ja3",
    client_type: "Chrome 109",
    description: "Chrome 109 on Windows 7",
  },
  {
    fingerprint: "chrome_108_ja3",
    client_type: "Chrome 108",
    description: "Chrome 108 on macOS 12",
  },
  {
    fingerprint: "chrome_107_ja3",
    client_type: "Chrome 107",
    description: "Chrome 107 on Android 12",
  },
  {
    fingerprint: "chrome_106_ja3",
    client_type: "Chrome 106",
    description: "Chrome 106 on iOS 15",
  },
  {
    fingerprint: "chrome_105_ja3",
    client_type: "Chrome 105",
    description: "Chrome 105 on Windows 8",
  },

  // Microsoft Edge
  {
    fingerprint: "edge_120_ja3",
    client_type: "Edge 120",
    description: "Edge 120 on Windows 11",
  },
  {
    fingerprint: "edge_119_ja3",
    client_type: "Edge 119",
    description: "Edge 119 on Windows 10",
  },
  {
    fingerprint: "edge_118_ja3",
    client_type: "Edge 118",
    description: "Edge 118 on macOS",
  },
  {
    fingerprint: "edge_117_ja3",
    client_type: "Edge 117",
    description: "Edge 117 on Linux",
  },
  {
    fingerprint: "edge_116_ja3",
    client_type: "Edge 116",
    description: "Edge 116 on Android",
  },
  {
    fingerprint: "edge_115_ja3",
    client_type: "Edge 115",
    description: "Edge 115 on iOS",
  },
  {
    fingerprint: "edge_114_ja3",
    client_type: "Edge 114",
    description: "Edge 114 on Windows Server",
  },

  // Opera
  {
    fingerprint: "opera_106_ja3",
    client_type: "Opera 106",
    description: "Opera 106 on Windows 11",
  },
  {
    fingerprint: "opera_105_ja3",
    client_type: "Opera 105",
    description: "Opera 105 on Windows 10",
  },
  {
    fingerprint: "opera_104_ja3",
    client_type: "Opera 104",
    description: "Opera 104 on macOS",
  },
  {
    fingerprint: "opera_103_ja3",
    client_type: "Opera 103",
    description: "Opera 103 on Linux",
  },
  {
    fingerprint: "opera_102_ja3",
    client_type: "Opera 102",
    description: "Opera 102 on Android",
  },

  // Vivaldi & Brave
  {
    fingerprint: "brave_161_ja3",
    client_type: "Brave 1.61",
    description: "Brave Browser 1.61 on Windows",
  },
  {
    fingerprint: "brave_160_ja3",
    client_type: "Brave 1.60",
    description: "Brave Browser 1.60 on macOS",
  },
  {
    fingerprint: "vivaldi_65_ja3",
    client_type: "Vivaldi 6.5",
    description: "Vivaldi Browser 6.5 on Linux",
  },
  {
    fingerprint: "vivaldi_64_ja3",
    client_type: "Vivaldi 6.4",
    description: "Vivaldi Browser 6.4 on Windows",
  },

  // Tor Browser
  {
    fingerprint: "tor_130_ja3",
    client_type: "Tor Browser 13.0",
    description: "Tor Browser 13.0 based on Firefox ESR",
  },
  {
    fingerprint: "tor_125_ja3",
    client_type: "Tor Browser 12.5",
    description: "Tor Browser 12.5 on Linux",
  },

  // Mobile WebKit / Safari versions
  {
    fingerprint: "safari_ios_16_ja3",
    client_type: "Safari iOS 16",
    description: "Safari on iOS 16.5",
  },
  {
    fingerprint: "safari_ios_15_ja3",
    client_type: "Safari iOS 15",
    description: "Safari on iOS 15.2",
  },
  {
    fingerprint: "safari_macos_16_ja3",
    client_type: "Safari macOS 16",
    description: "Safari 16 on macOS 13",
  },
  {
    fingerprint: "safari_macos_15_ja3",
    client_type: "Safari macOS 15",
    description: "Safari 15 on macOS 12",
  },

  // curl versions
  {
    fingerprint: "curl_84_ja3",
    client_type: "curl 8.4.0",
    description: "curl 8.4.0 with OpenSSL 3.1.4",
  },
  {
    fingerprint: "curl_83_ja3",
    client_type: "curl 8.3.0",
    description: "curl 8.3.0 with OpenSSL 3.0.10",
  },
  {
    fingerprint: "curl_82_ja3",
    client_type: "curl 8.2.1",
    description: "curl 8.2.1 with GnuTLS 3.8.1",
  },
  {
    fingerprint: "curl_81_ja3",
    client_type: "curl 8.1.2",
    description: "curl 8.1.2 with Schannel on Windows",
  },
  {
    fingerprint: "curl_80_ja3",
    client_type: "curl 8.0.1",
    description: "curl 8.0.1 with SecureTransport on macOS",
  },
  {
    fingerprint: "curl_78_ja3",
    client_type: "curl 7.88.1",
    description: "curl 7.88.1 with OpenSSL 1.1.1",
  },
  {
    fingerprint: "curl_77_ja3",
    client_type: "curl 7.79.1",
    description: "curl 7.79.1 with OpenSSL",
  },
  {
    fingerprint: "curl_76_ja3",
    client_type: "curl 7.64.0",
    description: "curl 7.64.0 on Debian",
  },

  // HTTP Library Clients
  {
    fingerprint: "golang_121_ja3",
    client_type: "Go 1.21 HTTP",
    description: "Go 1.21 net/http client",
  },
  {
    fingerprint: "golang_120_ja3",
    client_type: "Go 1.20 HTTP",
    description: "Go 1.20 net/http client",
  },
  {
    fingerprint: "golang_119_ja3",
    client_type: "Go 1.19 HTTP",
    description: "Go 1.19 net/http",
  },
  {
    fingerprint: "python_urllib3_ja3",
    client_type: "Python urllib3",
    description: "Python urllib3 HTTP library",
  },
  {
    fingerprint: "python_httpx_ja3",
    client_type: "Python httpx",
    description: "Python HTTPX async client",
  },
  {
    fingerprint: "python_aiohttp_ja3",
    client_type: "Python aiohttp",
    description: "Python aiohttp client",
  },
  {
    fingerprint: "java_okhttp_ja3",
    client_type: "OkHttp Java",
    description: "Square OkHttp client for Java/Android",
  },
  {
    fingerprint: "java_resttemplate_ja3",
    client_type: "Spring RestTemplate",
    description: "Spring RestTemplate client",
  },
  {
    fingerprint: "nodejs_axios_ja3",
    client_type: "Node.js Axios",
    description: "Axios client on Node.js",
  },
  {
    fingerprint: "nodejs_undici_ja3",
    client_type: "Node.js Undici",
    description: "Undici HTTP client in Node.js 18+",
  },

  // Scripting and Automation languages
  {
    fingerprint: "perl_lwp_ja3",
    client_type: "Perl LWP",
    description: "Perl LWP::UserAgent client",
  },
  {
    fingerprint: "ruby_net_http_ja3",
    client_type: "Ruby Net::HTTP",
    description: "Ruby Net::HTTP standard client",
  },
  {
    fingerprint: "php_curl_ja3",
    client_type: "PHP cURL",
    description: "PHP cURL extension client",
  },
  {
    fingerprint: "powershell_webrequest_ja3",
    client_type: "PowerShell WebRequest",
    description: "PowerShell Invoke-WebRequest client",
  },
  {
    fingerprint: "dotnet_httpclient_ja3",
    client_type: ".NET HttpClient",
    description: ".NET Core HttpClient",
  },

  // Security Scanners & Auditors
  {
    fingerprint: "nmap_ssl_scan_ja3",
    client_type: "Nmap Scripting Engine",
    description: "Nmap NSE SSL/TLS scanner",
  },
  {
    fingerprint: "masscan_tls_ja3",
    client_type: "Masscan",
    description: "Masscan TLS banner grabber",
  },
  {
    fingerprint: "zgrab2_ja3",
    client_type: "ZGrab2",
    description: "ZGrab2 TLS application scanner",
  },
  {
    fingerprint: "nikto_web_scanner_ja3",
    client_type: "Nikto",
    description: "Nikto Web Vulnerability Scanner",
  },
  {
    fingerprint: "nessus_vulnerability_ja3",
    client_type: "Nessus",
    description: "Nessus vulnerability scanner TLS client",
  },

  // Malware & Botnets (Commonly monitored in TLS audits)
  {
    fingerprint: "trickbot_malware_ja3",
    client_type: "Trickbot Malware",
    description: "Trickbot banking trojan TLS signature",
  },
  {
    fingerprint: "emotet_malware_ja3",
    client_type: "Emotet Malware",
    description: "Emotet loader TLS signature",
  },
  {
    fingerprint: "cobaltstrike_beacon_ja3",
    client_type: "Cobalt Strike Beacon",
    description: "Cobalt Strike beacon default HTTPS profile",
  },
  {
    fingerprint: "metasploit_reverse_ja3",
    client_type: "Metasploit Stager",
    description: "Metasploit reverse HTTPS stager",
  },
  {
    fingerprint: "mirai_botnet_ja3",
    client_type: "Mirai Botnet",
    description: "Mirai IoT botnet C2 client signature",
  },
  {
    fingerprint: "qakbot_malware_ja3",
    client_type: "Qakbot Loader",
    description: "Qakbot malware loader TLS",
  },
  {
    fingerprint: "lokibot_ja3",
    client_type: "LokiBot Infostealer",
    description: "LokiBot infostealer client",
  },
  {
    fingerprint: "redline_stealer_ja3",
    client_type: "RedLine Stealer",
    description: "RedLine information stealer TLS C2",
  },

  // Ransomware families
  {
    fingerprint: "wannacry_ransomware_ja3",
    client_type: "WannaCry",
    description: "WannaCry ransomware stager",
  },
  {
    fingerprint: "petya_ransomware_ja3",
    client_type: "NotPetya",
    description: "NotPetya ransomware wiper",
  },
  {
    fingerprint: "ryuk_ransomware_ja3",
    client_type: "Ryuk",
    description: "Ryuk ransomware network beacon",
  },
  {
    fingerprint: "maze_ransomware_ja3",
    client_type: "Maze",
    description: "Maze ransomware C2 client",
  },
  {
    fingerprint: "lockbit_ransomware_ja3",
    client_type: "LockBit",
    description: "LockBit ransomware network stager",
  },
  {
    fingerprint: "revil_ransomware_ja3",
    client_type: "REvil",
    description: "REvil/Sodinokibi ransomware C2",
  },
  {
    fingerprint: "darkside_ransomware_ja3",
    client_type: "DarkSide",
    description: "DarkSide ransomware C2",
  },
  {
    fingerprint: "blackcat_ransomware_ja3",
    client_type: "BlackCat",
    description: "BlackCat ALPHV ransomware",
  },
  {
    fingerprint: "clop_ransomware_ja3",
    client_type: "Clop",
    description: "Clop ransomware data exfiltration",
  },
  {
    fingerprint: "conti_ransomware_ja3",
    client_type: "Conti",
    description: "Conti ransomware C2 beacon",
  },

  // Banking trojans & loaders
  {
    fingerprint: "dridex_malware_ja3",
    client_type: "Dridex",
    description: "Dridex banking trojan",
  },
  {
    fingerprint: "ursnif_malware_ja3",
    client_type: "Ursnif",
    description: "Ursnif/Gozi loader C2",
  },
  {
    fingerprint: "icedid_malware_ja3",
    client_type: "IcedID",
    description: "IcedID/BokBot banking trojan",
  },
  {
    fingerprint: "bazaLoader_malware_ja3",
    client_type: "BazaLoader",
    description: "BazaLoader download stager",
  },
  {
    fingerprint: "bumblebee_malware_ja3",
    client_type: "Bumblebee",
    description: "Bumblebee malware loader",
  },
  {
    fingerprint: "smokeloader_malware_ja3",
    client_type: "SmokeLoader",
    description: "SmokeLoader stager",
  },
  {
    fingerprint: "agenttesla_malware_ja3",
    client_type: "AgentTesla",
    description: "AgentTesla keylogger/stealer",
  },
  {
    fingerprint: "formbook_malware_ja3",
    client_type: "Formbook",
    description: "Formbook infostealer client",
  },
  {
    fingerprint: "nanocore_malware_ja3",
    client_type: "NanoCore",
    description: "NanoCore RAT client",
  },

  // Remote Access Trojans (RATs)
  {
    fingerprint: "netwire_rat_ja3",
    client_type: "NetWire",
    description: "NetWire RAT client",
  },
  {
    fingerprint: "remcos_rat_ja3",
    client_type: "Remcos",
    description: "Remcos RAT surveillance client",
  },
  {
    fingerprint: "njrat_malware_ja3",
    client_type: "njRAT",
    description: "njRAT/Bladabindi client stager",
  },
  {
    fingerprint: "darkcomet_rat_ja3",
    client_type: "DarkComet",
    description: "DarkComet RAT client",
  },
  {
    fingerprint: "quasarrat_malware_ja3",
    client_type: "QuasarRAT",
    description: "QuasarRAT open-source RAT",
  },
  {
    fingerprint: "asyncrat_malware_ja3",
    client_type: "AsyncRAT",
    description: "AsyncRAT open-source RAT",
  },
  {
    fingerprint: "warzone_rat_ja3",
    client_type: "Warzone RAT",
    description: "Warzone RAT surveillance agent",
  },
  {
    fingerprint: "plugx_rat_ja3",
    client_type: "PlugX",
    description: "PlugX RAT backchannel beacon",
  },
  {
    fingerprint: "shadowpad_rat_ja3",
    client_type: "ShadowPad",
    description: "ShadowPad modular RAT",
  },

  // APT groups and nation-state profiles
  {
    fingerprint: "apt1_malware_ja3",
    client_type: "APT1",
    description: "APT1 comment group malware client",
  },
  {
    fingerprint: "apt28_fancybear_ja3",
    client_type: "Fancy Bear",
    description: "APT28 Fancy Bear stager",
  },
  {
    fingerprint: "apt29_cozybear_ja3",
    client_type: "Cozy Bear",
    description: "APT29 Cozy Bear C2 stager",
  },
  {
    fingerprint: "apt41_doubledragon_ja3",
    client_type: "Double Dragon",
    description: "APT41 Double Dragon spy stager",
  },
  {
    fingerprint: "lazarus_group_ja3",
    client_type: "Lazarus Group",
    description: "Lazarus Group North Korea C2",
  },
  {
    fingerprint: "kimsuky_malware_ja3",
    client_type: "Kimsuky",
    description: "Kimsuky group campaign profile",
  },
  {
    fingerprint: "sandworm_group_ja3",
    client_type: "Sandworm",
    description: "Sandworm group cyberweapon profile",
  },
  {
    fingerprint: "muddywater_ja3",
    client_type: "MuddyWater",
    description: "MuddyWater group campaign profile",
  },
  {
    fingerprint: "turla_group_ja3",
    client_type: "Turla",
    description: "Turla group spy network profile",
  },

  // Bot signatures
  {
    fingerprint: "bot_chrome_ja3",
    client_type: "Bot (Chrome)",
    description: "Automated Chrome bot agent",
  },
  {
    fingerprint: "bot_firefox_ja3",
    client_type: "Bot (Firefox)",
    description: "Automated Firefox bot agent",
  },
  {
    fingerprint: "bot_safari_ja3",
    client_type: "Bot (Safari)",
    description: "Automated Safari bot agent",
  },
  {
    fingerprint: "bot_edge_ja3",
    client_type: "Bot (Edge)",
    description: "Automated Edge bot agent",
  },
  {
    fingerprint: "bot_opera_ja3",
    client_type: "Bot (Opera)",
    description: "Automated Opera bot agent",
  },
  {
    fingerprint: "bot_tor_ja3",
    client_type: "Bot (Tor)",
    description: "Automated Tor bot agent",
  },
  {
    fingerprint: "bot_curl_ja3",
    client_type: "Bot (curl)",
    description: "Automated curl bot agent",
  },
  {
    fingerprint: "bot_python_ja3",
    client_type: "Bot (Python)",
    description: "Automated Python requests scraper",
  },
  {
    fingerprint: "bot_golang_ja3",
    client_type: "Bot (Go)",
    description: "Automated Go http scraper",
  },
  {
    fingerprint: "bot_nodejs_ja3",
    client_type: "Bot (Node.js)",
    description: "Automated Node.js scraper",
  },
]

///|
let server_db_ext : Array[FingerprintEntry] = [
  // Nginx Versions
  {
    fingerprint: "nginx_124_ja4s",
    client_type: "Nginx 1.24",
    description: "Nginx 1.24 Server Hello",
  },
  {
    fingerprint: "nginx_122_ja4s",
    client_type: "Nginx 1.22",
    description: "Nginx 1.22 Server Hello",
  },
  {
    fingerprint: "nginx_120_ja4s",
    client_type: "Nginx 1.20",
    description: "Nginx 1.20 Server Hello",
  },
  {
    fingerprint: "nginx_118_ja4s",
    client_type: "Nginx 1.18",
    description: "Nginx 1.18 Server Hello",
  },

  // Apache HTTPD Versions
  {
    fingerprint: "apache_2458_ja4s",
    client_type: "Apache 2.4.58",
    description: "Apache HTTPD 2.4.58",
  },
  {
    fingerprint: "apache_2454_ja4s",
    client_type: "Apache 2.4.54",
    description: "Apache HTTPD 2.4.54",
  },
  {
    fingerprint: "apache_2441_ja4s",
    client_type: "Apache 2.4.41",
    description: "Apache HTTPD 2.4.41",
  },

  // IIS Server Hello configurations
  {
    fingerprint: "iis_10_win2022_ja4s",
    client_type: "IIS 10.0 Win2022",
    description: "IIS 10 on Windows Server 2022",
  },
  {
    fingerprint: "iis_10_win2016_ja4s",
    client_type: "IIS 10.0 Win2016",
    description: "IIS 10 on Windows Server 2016",
  },
  {
    fingerprint: "iis_85_win2012r2_ja4s",
    client_type: "IIS 8.5 Win2012R2",
    description: "IIS 8.5 on Windows Server 2012 R2",
  },

  // CDN Providers
  {
    fingerprint: "cloudflare_edge_ja4s",
    client_type: "Cloudflare Edge",
    description: "Cloudflare Global Edge Server Hello",
  },
  {
    fingerprint: "akamai_edge_ja4s",
    client_type: "Akamai CDN",
    description: "Akamai CDN Edge Server Hello",
  },
  {
    fingerprint: "fastly_edge_ja4s",
    client_type: "Fastly CDN",
    description: "Fastly CDN Edge Server Hello",
  },
  {
    fingerprint: "cloudfront_edge_ja4s",
    client_type: "AWS CloudFront",
    description: "AWS CloudFront Server Hello",
  },

  // Hardware Load Balancers
  {
    fingerprint: "f5_bigip_ja4s",
    client_type: "F5 BIG-IP",
    description: "F5 BIG-IP Local Traffic Manager Server Hello",
  },
  {
    fingerprint: "citrix_adc_ja4s",
    client_type: "Citrix ADC",
    description: "Citrix ADC NetScaler Server Hello",
  },
]

///|
pub fn lookup_client_fingerprint_ext(fp : String) -> String? {
  for entry in client_db_ext {
    if entry.fingerprint == fp {
      return Some(entry.client_type + ": " + entry.description)
    }
  }
  None
}

///|
pub fn lookup_server_fingerprint_ext(fp : String) -> String? {
  for entry in server_db_ext {
    if entry.fingerprint == fp {
      return Some(entry.client_type + ": " + entry.description)
    }
  }
  None
}
