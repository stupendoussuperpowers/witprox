FROM golang:1.24 AS builder
WORKDIR /build 

RUN git clone -b network-tracing https://github.com/stupendoussuperpowers/witness.git
RUN git clone -b network-tracing https://github.com/stupendoussuperpowers/go-witness.git

WORKDIR /build/witness
RUN go mod edit -replace github.com/in-toto/go-witness=../go-witness && go mod tidy
RUN go build -o /witprox-bin/witness .

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND noninteractive
ENV container docker
WORKDIR /build 

RUN apt-get update && \
    apt-get install -y \
    	sudo \
	git \
	make \
	jq \
	curl \
	vim \
	npm \
	gcc \
	clang \
	llvm \
	libbpf-dev \
	golang-go \
	iproute2 \
	iputils-ping \
	ca-certificates \
	linux-tools-common \
	linux-tools-6.8.0-64-generic \
	linux-tools-generic && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

ENV PATH "/usr/lib/linux-tools/6.8.0-64-generic:${PATH}"

COPY . /src/witprox 

WORKDIR /src
RUN git clone https://github.com/stupendoussuperpowers/goproxy.git

WORKDIR /src/witprox 
RUN go mod edit -replace github.com/elazarl/goproxy=../goproxy && go mod tidy
RUN make all 

RUN cp proxy /usr/local/bin/witprox

RUN mkdir -p /sys/fs/bpf /sys/fs/cgroup 

COPY --from=builder /witprox-bin/witness /usr/local/bin/witness

COPY entry.sh /usr/local/bin/entry.sh 
RUN chmod +x /usr/local/bin/entry.sh 

WORKDIR /root 
CMD ["/usr/local/bin/entry.sh"]
