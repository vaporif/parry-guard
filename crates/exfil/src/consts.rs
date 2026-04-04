//! Constant arrays used across exfil detection modules.

pub const NETWORK_SINKS: &[&str] = &[
    "curl", "wget", "http", "https", "xh", "curlie", "httpie", "aria2c", "axel", "wge", "curlx",
    "nc", "ncat", "netcat", "telnet", "socat", "openssl", "ssh", "scp", "sftp", "rsync", "ftp",
    "lftp", "rcp", "nslookup", "dig", "host", "aws", "gcloud", "gsutil", "az", "s3cmd", "rclone",
    "azcopy", "git",
];

// Cloud storage upload commands (always suspicious with sensitive data)
pub const CLOUD_UPLOAD_COMMANDS: &[&str] = &[
    "aws s3 cp",
    "aws s3 mv",
    "aws s3 sync",
    "gsutil cp",
    "gsutil rsync",
    "az storage blob upload",
    "az storage file upload",
    "azcopy copy",
    "rclone copy",
    "rclone sync",
    "s3cmd put",
];

// Clipboard tools (data can be exfiltrated via copy-paste)
pub const CLIPBOARD_TOOLS: &[&str] = &[
    "pbcopy",   // macOS
    "xclip",    // Linux X11
    "xsel",     // Linux X11
    "wl-copy",  // Wayland
    "clip.exe", // Windows/WSL
];

// Flagged unconditionally (no sensitive source required)
pub const DNS_EXFIL_TOOLS: &[&str] = &[
    "dnscat", "dnscat2", "iodine", "iodined", "dns2tcp", "dnsexfil",
];

pub const SENSITIVE_SOURCES: &[&str] = &[
    "cat", "head", "tail", "less", "more", "tee", "env", "printenv", "whoami", "id", "hostname",
    "aws", "gcloud", "az", "pass", "gpg", "security", "kubectl",
];

pub const INTERPRETERS: &[&str] = &[
    "python",
    "python2",
    "python3",
    "pypy",
    "pypy3",
    "node",
    "nodejs",
    "deno",
    "bun",
    "ruby",
    "jruby",
    "perl",
    "php",
    "php-cgi",
    "lua",
    "pwsh",
    "powershell",
    "Rscript",
    "elixir",
    "julia",
    "swift",
    "crystal",
    "tclsh",
    "wish",
    "groovy",
    "scala",
    "kotlin",
    "kotlinc",
    "jshell",
    "osascript",
    "nix",
    "nix-shell",
    "nix-build",
    "nix-instantiate",
    "awk",
    "gawk",
    "mawk",
    "nawk",
    "sed",
    "gsed",
];

pub const SHELL_INTERPRETERS: &[&str] = &[
    "bash", "sh", "zsh", "dash", "ksh", "mksh", "oksh", "pdksh", "fish", "ash", "csh", "tcsh",
    "yash", "rc", "es",
];

pub const INLINE_CODE_FLAGS: &[&str] = &[
    "-c", "-e", "-r", "--eval", "eval", "-script", "--expr", "--run",
];

pub const CODE_NETWORK_INDICATORS: &[&str] = &[
    // Python (TCP/UDP/HTTP)
    "urllib",
    "urlopen",
    "requests.post",
    "requests.get",
    "requests.put",
    "http.client",
    "socket.connect",
    "socket.create_connection",
    "socket.socket",
    "sock_dgram",
    "sock_stream",
    // Node/JS (TCP/UDP/HTTP)
    "fetch(",
    "http.request",
    "https.request",
    "net.connect",
    "net.createconnection",
    "net.socket",
    "dgram.createsocket",
    "dgram.bind",
    "axios",
    // Ruby (TCP/UDP/HTTP)
    "net::http",
    "tcpsocket",
    "udpsocket",
    "socket.new",
    "open-uri",
    // Perl (TCP/UDP)
    "io::socket",
    "io::socket::inet",
    "lwp::",
    "http::request",
    // PHP (TCP/UDP)
    "curl_exec",
    "file_get_contents('http",
    "file_get_contents(\"http",
    "fsockopen",
    "pfsockopen",
    "stream_socket_client",
    "fopen('http",
    "fopen(\"http",
    // Lua (TCP/UDP)
    "socket.http",
    "socket.tcp",
    "socket.udp",
    // Deno/Bun
    "deno.open",
    "deno.connect",
    "bun.connect",
    // PowerShell (TCP/UDP)
    "invoke-webrequest",
    "invoke-restmethod",
    "new-object net.webclient",
    "system.net.webclient",
    "downloadstring",
    "uploadstring",
    "net.sockets",
    "tcpclient",
    "udpclient",
    // R
    "download.file",
    "httr::",
    "curl::curl",
    "url(",
    "readlines(url",
    "socketconnection",
    // Elixir
    "httpoison",
    ":httpc",
    ":gen_tcp",
    ":gen_udp",
    "finch",
    "req.post",
    "req.get",
    // Julia
    "http.jl",
    "downloads.download",
    "http.request",
    // Tcl
    "http::geturl",
    // JVM scripting (Groovy/Scala/Kotlin)
    "url.text",
    "url.openconnection",
    "httpurlconnection",
    "java.net.url",
    "java.net.socket",
    "java.net.datagramsocket",
    "datagramsocket",
    "serversocket",
    "okhttp",
    "httpget",
    "httppost",
    // macOS osascript
    "do shell script",
    "nsurl",
    "nsurlrequest",
    // Go (inline via interpreters)
    "net.dial",
    "net.listen",
];
