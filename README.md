## Witness daemon: Network attestations

Witprox serves as a witness daemon to support network attestations through eBPF, and a MITM proxy to decrypt and log any TCP traffic for a given command.  

Integrations with `witness` and `go-witness` are staged here:

[stupendoussuperpowers/witness](https://github.com/stupendoussuperpowers/witness/tree/network-tracing)

[stupendoussuperpowers/go-witness](https://github.com/stupendoussuperpowers/go-witness/tree/network-tracing)

### Running

Through dockerhub:

```
docker pull stupendoussuperpowers/witness-ubuntu # Pull docker image.
docker run -it --privileged stupendoussuperpowers/witness-ubuntu # Run image with elevated privileges to enable eBPF and cgroup management.

... 
# Generate a network attestation 
$> witness run -o test-att.json --step build --network -- <build command>
```

For MacOS, use [`colima`](https://github.com/abiosoft/colima):

`colima start`

### Building 

To build from source:

```
git clone https://github.com/stupendoussuperpowers/witprox.git && cd witprox
docker build -t witness-ubuntu .

... 
# Generate a network attestation 
$> witness run -o test-att.json --step build --network -- <build command>
```

### Internals

To capture network traffic, we require a MITM proxy running on localhost, and eBPF programs which can tag and redirect network packets to this proxy server. 

#### Transparent Proxy 
For TLS, a trusted certificate is required. During initialization, `witprox` generates and installs a certificate to the client machine's trusted store. 

The TLS proxy breaks down client requests into two separate TLS connecions: `client <-1-> proxy <-2-> original target`.

 This allows the proxy to decrypt and log traffic. The `elazarl/goproxy` package handles most of the MITM for certificate management with the client.

Proxies are transparent so programs don't need modifications as long as any traffic intended for logging is redirected to the correct ports. Some ways to achieve these are explored below.

Conversely, the proxy doesn't need any information about the processes either, it just takes as input HTTP/TLS packets and redirects it back to the calling process after logging.

`witprox` records every network call made by a process into a dedicated file (named after its PID), which can later be read by the witness command-run attestor.

#### Redirection and Tagging. 

eBPF is used to tag network packets with a PID and the original destination, and then to redirect this to the MITM proxy. 

Any process in need of network capture must run in the `redirect` cgroup, and the proxy server must run in the `witprox` cgroup. 

The `witprox` binary is designed to be a long running daemon, which is responsible for all setups and cleanups required for running these eBPF programs. 

Upon start, the following setup actions are performed:

1. Check for existing TLS certificate at the provided path. 
2. Install this certificate if not already installed. 
3. Use the `witnessd.pid` file to ensure only one instance of `witprox` is running.
4. Create the `redirect` and `witprox` cgroups, load, pin and attach all maps and programs to these cgroups. 
5. Launch TCP and UDP proxy servers inside `witprox`. 

#### Generating Attestations

Network attestations are designed as an extension to the `command-run` attestor. 

When the `witness run` is used with `--network`, it first ensures that `witprox` is running, and then launches the build command inside the `redirect` cgroups. This ensures that network logs are stored in `/tmp/tls.<PID>`. 

While generating the final attestations, along with reporting `openedfiles`, we also store `networkcalls`, which are read  from the `/tmp/tls.<PID>` file mentioned earlier. 

The new schema for `command-run` can be seen [here](https://github.com/stupendoussuperpowers/go-witness/blob/network-tracing/schemagen/command-run.json).

--- 
### Command Line Flags


| Argument | Default Value | Description | 
| -------- | ------------- | ----------- |
| `--verbose` | `false` | Enable verbose logs for `goproxy` TLS server.|
| `--log` | `/tmp/` | Log folder for `witprox` and network logs. | 
| `--cert-path` | `/tmp/witproxca.crt` | TLS Certificate Path | 
| `--key-path` | `/tmp/witproxkey.pem` | TLS Certificate Key Path | 
| `--servers` | `false` | Only run the proxy servers without any setup. 

