FROM golang:1.24 AS builder
WORKDIR /build 

RUN git clone -b network-tracing https://github.com/stupendoussuperpowers/witness.git
RUN git clone -b network-tracing https://github.com/stupendoussuperpowers/go-witness.git

WORKDIR /build/witness
RUN go mod edit -replace github.com/in-toto/go-witness=../go-witness && go mod tidy
RUN go build -o ./bin/witness ./main.go 

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV container=docker
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

ENV PATH="/usr/lib/linux-tools/6.8.0-64-generic:${PATH}"

COPY . /src/witprox

WORKDIR /src/witprox

RUN go mod tidy
RUN make all
RUN ln ./bin/witnessd /usr/bin/witnessd

RUN mkdir -p /sys/fs/bpf /sys/fs/cgroup 

COPY --from=builder /build/witness/bin/witness /usr/bin/witness

COPY ./entry.sh /usr/bin/entry.sh 
RUN chmod +x /usr/bin/entry.sh 

WORKDIR /root 
CMD ["/usr/bin/entry.sh"] 
