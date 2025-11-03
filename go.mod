module github.com/stupendoussuperpowers/witprox

go 1.24.0

require (
	github.com/cilium/ebpf v0.19.0
	github.com/elazarl/goproxy v1.7.2
	github.com/google/uuid v1.6.0
	golang.org/x/crypto v0.42.0
	golang.org/x/net v0.43.0
	golang.org/x/sys v0.36.0
)

require golang.org/x/text v0.29.0 // indirect

replace github.com/elazarl/goproxy => github.com/stupendoussuperpowers/goproxy v1.7.3
