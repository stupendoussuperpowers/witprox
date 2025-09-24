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

If using the default port, redirect all `tcp` traffic to `localhost:1230`. The proxy detects whether the traffic is HTTP, TLS, or a raw socket, and logs the requests accordingly.

Two simple ways to achieve this:

- **iptables**
    
    For linux systems, `iptables` can be used to [redireect traffic](https://linux.die.net/man/8/iptables#:~:text=raw%20table.-,REDIRECT,-This%20target%20is) that meets a certain set of requirements to a local port. In the example below we are redirecting all `tcp` traffic to the default port of our proxy `1230` from `builduser`. 

    ```
    sudo iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner builduser -j REDIRECT --to-ports 1230
    ```    

    `iptables` can also be used in several complex configurations depending on which traffic requires monitoring.

    This is the approach adopted by oss-rebuild as well.

- **LD_PRELOAD**

    We can also preload the `connect()` syscall, and manually edit the destination address and port if the network is a TCP packet headed to port `443` or `80`. An example `LD_PRELOAD` code is present in `internal/connectldp.c`

    Compile using:

    `cc -shared -fPIC -o connectldp.so connectldp.c -ldl`

    Example usage:

    `LD_PRELOAD=/path/to/connectldp.so npm install --prefer-online`

    This approach is much more limited, given that all programs to be monitored need to be LD_PRELOAD'd individually. It's also much harder to describe filters.

[UDP]

UDP proxy works by binding our UDP server to `0.0.0.0` with `IP_TRANSPARENT` and `IP_RECVORGDSTADDR` flags on the socket. These socket options allow the kernel to preserve the original destination address of incoming packets which are later extracted from the out-of-band data associated with that packet.

Unlike TCP, UDP is connectionless, this introduces a few challenges:

- Each packet needs to be handled individually, and we must ensure that the server responses we relay back to client appear to come from the original destination (IP, Port). This requires us to spoof our address while sending this message back to the client. 

- With TCP, we need no setup to determine the original IP address, we can achieve that by getting the `SO_ORIGINAL_DST` socket option on the connection. This approach does not work on UDP out of the box, and we need to use the `IP_RECVORIGDSTADDR` flag to ensure this data is stored in the out-of-band data of the packet.

The current setup relies on `TPROXY` rules in `iptables`, which mark and redirect the relevant UDP traffic to our proxy. These rules can be found in `setup_udp_proxy.sh`. 

---
### Sample Logs

By default all logs are stored in `/tmp/witprox.log` for both TCP and UDP traffic.

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
| `--log` |  `/tmp/witprox.log` | Log file for requests | 
