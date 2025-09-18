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

If using default ports, redirect all `:443` traffic to `localhost:1234` and `:80` traffic to `localhost:1233`. For custom ports, redirect `:443` traffic to `localhost:<tls-port>` and `:80` traffic to `localhost:<http-port>`.

Two simple ways to achieve these:

- **iptables**
    
    For linux systems, `iptables` can be used to [redireect traffic](https://linux.die.net/man/8/iptables#:~:text=raw%20table.-,REDIRECT,-This%20target%20is) that meets a certain set of requirements to a local port. In the example below we are redirecting all `tcp` traffic to the default port of our proxy `1230` from `builduser`. 

    ```
    sudo iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner builduser -j REDIRECT --to-ports 1230
    ```
    
    The proxy detects whether the traffic is HTTP, TLS, or a raw socket, and logs the requests accordingly.

    `iptables` can also be used in several complex configurations depending on which traffic requires monitoring.

    This is the approach adopted by oss-rebuild as well.

- **LD_PRELOAD**

    We can also preload the `connect()` syscall, and manually edit the destination address and port if the network is a TCP packet headed to port `443` or `80`. An example `LD_PRELOAD` code is present in `internal/connectldp.c`

    Compile using:

    `cc -shared -fPIC -o connectldp.so connectldp.c -ldl`

    Example usage:

    `LD_PRELOAD=/path/to/connectldp.so npm install --prefer-online`

    This approach is much more limited, given that all programs to be monitored need to be LD_PRELOAD'd individually. It's also much harder to describe filters.
  
---
### Sample Logs

By default the logs are stored in `/tmp/witprox.tls.log` and `/tmp/witprox.http.log`

Each HTTP(S) Request/Response pair is stored as JSON in these log files as a newline, which can be later inspected using tools such as `jq`. 

Example log from running `npm install is-even` - 

```
$> tail /tmp/witprox.tls.log | jq

{
  "timestamp": "2025-09-14T03:19:56.357272801Z",
  "duration_ms": 9223372036854,
  "method": "GET",
  "url": "https://registry.npmjs.org:443/is-even/-/is-even-1.0.0.tgz",
  "status_code": 200,
  "client_addr": "127.0.0.1:58566",
  "bytes_sent": 0,
  "bytes_recv": 2163,
  "req_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "res_hash": "d77c6aeabdfb84feed20106b7533975fe68d17d1fa7969672ddf8efb2c37b60c",
  "req_headers": {
    "Accept": [
      "*/*"
    ],
    "Npm-Command": [
      "install"
    ],
    "Pacote-Integrity": [
      "sha512-LEhnkAdJqic4Dbqn58A0y52IXoHWlsueqQkKfMfdEnIYG8A1sm/GHidKkS6yvXlMoRrkM34csHnXQtOqcb+Jzg=="
    ],
    "Pacote-Pkg-Id": [
      "remote:is-even@https://registry.npmjs.org/is-even/-/is-even-1.0.0.tgz"
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
  "res_headers": {
    "Accept-Ranges": [
      "bytes"
    ],
    "Access-Control-Allow-Origin": [
      "*"
    ],
    "Age": [
      "213429"
    ],
    "Cache-Control": [
      "public, immutable, max-age=31557600"
    ],
    "Cf-Cache-Status": [
      "HIT"
    ],
    "Cf-Ray": [
      "97ecbee10b1a41ef-EWR"
    ],
    "Connection": [
      "keep-alive"
    ],
    "Content-Length": [
      "2163"
    ],
    "Content-Type": [
      "application/octet-stream"
    ],
    "Date": [
      "Sun, 14 Sep 2025 03:19:56 GMT"
    ],
    "Etag": [
      "\"009dcdfe3ddfc69d386f7abb26fe6d0c\""
    ],
    "Last-Modified": [
      "Sun, 27 May 2018 04:58:57 GMT"
    ],
    "Server": [
      "cloudflare"
    ],
    "Set-Cookie": [
      "_cfuvid=y8BEf03ZeLcLCE4LHR.R9s7eQM_POnNUB_BAex_jmpI-1757819996378-0.0.1.1-604800000; path=/; domain=.npmjs.org; HttpOnly; Secure; SameSite=None"
    ],
    "Vary": [
      "Accept-Encoding"
    ]
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
| `--port` | `1230` | Configure the TCP Port on localhost | 
| `--cert-path` | `/tmp/witproxca.crt` | TLS Certificate Path | 
| `--key-path` | `/tmp/witproxkey.pem` | TLS Certificate Key Path | 
| `--log` |  `/tmp/witprox.log` | Log file for requests | 
