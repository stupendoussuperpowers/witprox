Build with: `go build -o proxy -buildvcs=false main.go`

Generate a certificate first - 

`./proxy --generate-ca`

Trust this certificate on the client (example for Debian/Ubuntu) - 

```
cp /tmp/witprox-ca.pem /usr/local/share/ca-certificates/

cp /tmp/witprox-key.pem /usr/local/share/ca-certificates/

update-ca-certificates`
```

Run proxy in the background - 

`./proxy`


--- 

If using default ports, we need to redirect all `:443` to `localhost:1234` and `:80` to `localhost:1233`

Currently, two simplest ways to do that are:

- iptables

```
sudo iptables -t nat -A OUTPUT -p tcp --dport 80 -m owner --uid-owner builduser -j REDIRECT --to-ports 1233

sudo iptables -t nat -A OUTPUT -p tcp --dport 443 -m owner --uid-owner builduser -j REDIRECT --to-ports 1234
```

This is an example use of iptables, here we assume that `builduser` is the user who's network requests we need to log. 

Now, if we run something like `npm install --prefer-online` through the `builduser`, we are able to log any TLS or HTTP calls that are made.

- LD_PRELOAD

We can also preload the `connect()` syscall, and manually edit the destination address and port if the network is a TCP packet headed to port 443 or 80. An example LD_PRELOAD code is present in `internal/connectldp.c`

Compile using:

`cc -shared -fPIC -o connectldp.so connectldp.c -ldl`

Example usage:

`LD_PRELOAD=/path/to/connectldp.so npm install --prefer-online`

--- 

By default the logs are stored in `/tmp/witprox.tls.log` and `/tmp/witprox.http.log`

Example log of one of the connections made by from a `npm install` - 

```
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
