BPF_DIR := internal/bpf
BPF_FLAGS := -O2 -g -target bpf 

GO_OUTPUT := witnessd

BPF_OUTPUT := $(BPF_DIR)/redirect.o $(BPF_DIR)/witprox.o 

.PHONY: all bpf build clean 

all: gen-header bpf build

gen-header: $(BPF_DIR)/vmlinux.h
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

$(BPF_DIR)/%.o: $(BPF_DIR)/%.bpf.c
	clang $(BPF_FLAGS) -c $< -o $@

bpf: $(BPF_OUTPUT)

build:
	mkdir -p bin
	go build -o ./bin/$(GO_OUTPUT) ./

clean: 
	rm -f $(BPF_OUTPUT) ./bin/$(GO_OUTPUT)
