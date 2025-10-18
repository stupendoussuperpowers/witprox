## Transparent Network Proxy

This repo provides a binary that runs transparent HTTP and TLS proxy servers that log request/response pairs to disk.

The HTTP proxy is straightforward. For TLS, a trusted certificate is required. This binary can generate certificates that can be added to the client machine's trusted store.

TLS proxy uses two TLS connecions: `client <-1-> proxy <-2-> original target`. This allows the proxy to decrypt and log traffic. The `goproxy` package handles most of the MITM for certificate management with the client.

Proxies are transparent so programs don't need modifications as long as any traffic intended for logging is redirected to the correct ports. Some ways to achieve these are explored below.

Conversely, the proxy doesn't need any information about the processes either, they just take as input HTTP/TLS traffic and redirect it back to the calling process after logging.

---

### Initial Configurations

#### 0. Build

`go build -o proxy -buildvcs=false main.go`

[TLS, TCP]

#### 1. Generate a certificate

`./proxy --generate-ca`

#### 2. Trust this certificate on the client (example for Debian/Ubuntu) - 

```
cp /tmp/witproxca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

If using a certificate that is already trusted by the client, skip `--generate-ca` flow and use `--cert-path` to provide this certificate.

`oss-rebuild` wraps individual package managers. It provides environment variables to ensure the package manager trusts the certificates it generates. (For e.g. `PIP_CERT` for `pip`, `CURL_CA_BUNDLE` for `curl` , `NODE_EXTRA_CA_CERTS` for `npm`). This removes the need for a globally trusted certificate on the client machine.

#### 3. Run proxy in the background

`./proxy`

#### 4. Redirect traffic to proxies

When using with the `--setup` flag, traffic redirection is handled by:

 1. Setting up two cgroups, `witprox`: for the proxy servers, and `redirect` for any processes that need monitoring. 
 2. Loading the eBPF programs and maps in `internal/bpf` to the corresponding cgroups. 
 3. Upon exit, these cgroups and eBPF pinnings are cleaned up. 

If using the default port, redirect all `tcp` traffic to `localhost:1230`. The proxy detects whether the traffic is HTTP, TLS, or a raw socket, and logs the requests accordingly.

If manually redirecting traffic to the proxies, run with just the `--servers` flag. 

---
### Sample Logs

By default all logs are stored in `/tmp/tls.%PID` for both TCP and UDP traffic.

Each HTTP(S) Request/Response pair is stored as JSON in these log files as a newline, which can be later inspected using tools such as `jq`. 

Example log from running `npm install is-even` - 

```
{
  "protocol": "UDP",
  "client_addr": "172.17.0.2:57662",
  "dest_addr": "192.168.65.7:53",
  "hash": "0ab1c7036bb37542668698902eeed62ea75bd372b4f13a267bfeccfac7679f97",
  "timestamp": "2025-09-24T06:27:04.077426587Z",
  "type": "DNS",
  "body": {
    "ID": 29007,
    "is_query": true,
    "op_code": 0,
    "r_code": 0,
    "qd_count": 1,
    "an_count": 0,
    "ns_count": 0,
    "ar_count": 0,
    "question": "registry.npmjs.org.",
    "q_type": 1,
    "q_class": 1
  }
}

...

{
  "protocol": "TCP",
  "timestamp": "2025-09-24T06:27:04.506685254Z",
  "duration_ms": 124,
  "url": "https://registry.npmjs.org:443/is-odd/-/is-odd-3.0.1.tgz",
  "client_addr": "172.17.0.2:42102",
  "method": "GET",
  "status_code": 200,
  "req_body": {
    "headers": {
      "Accept": [
        "*/*"
      ],
      "Npm-Command": [
        "install"
      ],
      "Pacote-Integrity": [
        "sha512-CQpnWPrDwmP1+SMHXZhtLtJv90yiyVfluGsX5iNCVkrhQtU3TQHsUWPG9wkdk9Lgd5yNpAg9jQEo90CBaXgWMA=="
      ],
      "Pacote-Pkg-Id": [
        "remote:is-odd@https://registry.npmjs.org/is-odd/-/is-odd-3.0.1.tgz"
      ],
      "Pacote-Req-Type": [
        "tarball"
      ],
      "Pacote-Version": [
        "12.0.3"
      ],
      "User-Agent": [
        "npm/8.5.1 node/v12.22.9 linux x64 workspaces/false"
      ]
    },
    "bytes": 0,
    "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  },
  "res_body": {
    "headers": {
      "Accept-Ranges": [
        "bytes"
      ],
      "Access-Control-Allow-Origin": [
        "*"
      ],
      "Age": [
        "1831561"
      ],
      "Cache-Control": [
        "public, immutable, max-age=31557600"
      ],
      "Cf-Cache-Status": [
        "HIT"
      ],
      "Cf-Ray": [
        "984036c19f2f4a5f-EWR"
      ],
      "Connection": [
        "keep-alive"
      ],
      "Content-Length": [
        "2774"
      ],
      "Content-Type": [
        "application/octet-stream"
      ],
      "Date": [
        "Wed, 24 Sep 2025 06:27:04 GMT"
      ],
      "Etag": [
        "\"72202ddfef0f4a837b5483dfefaf662d\""
      ],
      "Last-Modified": [
        "Thu, 31 May 2018 20:16:49 GMT"
      ],
      "Server": [
        "cloudflare"
      ],
      "Set-Cookie": [
        "_cfuvid=YgEXbxYWa2hL_eHtcjsyJxh6g5AIuSIDiciHiDoTb6A-1758695224594-0.0.1.1-604800000; path=/; domain=.npmjs.org; HttpOnly; Secure; SameSite=None"
      ],
      "Vary": [
        "Accept-Encoding"
      ]
    },
    "bytes": 2774,
    "hash": "13c23b3f1f3a5c146b8906e23c8e674f8e4a6ff44b77720e1d4bddb7b2caf312"
  }
}
```

--- 
### Configurable Settings

Command line flags for `./proxy`

| Argument | Default Value | Description | 
| -------- | ------------- | ----------- |
| `--generate-ca` |  `false` | Generate a new TLS certificate and terminate early. | 
| `--verbose` | `false` | Enable verbose logs for `goproxy` TLS server.|
| `--tcp-port` | `1230` | Configure the TCP Port on localhost | 
| `--udp-port` | `2230` | Configure the UDP Port on localhost | 
| `--cert-path` | `/tmp/witproxca.crt` | TLS Certificate Path | 
| `--key-path` | `/tmp/witproxkey.pem` | TLS Certificate Key Path | 
| `--setup` | `false` | Run eBPF setups and clean up when running the proxy servers
| `--servers` | `false` | Only run the proxy servers without any setup. 
