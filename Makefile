BPF_DIR := internal/bpf
BPF_FLAGS := -O2 -g -target bpf 

GO_FILES := main.go setup.go
GO_OUTPUT := proxy

BPF_OUTPUT := $(BPF_DIR)/redirect.o $(BPF_DIR)/witprox.o 

.PHONY: all bpf build clean 

all: bpf build

$(BPF_DIR)/%.o: $(BPF_DIR)/%.bpf.c
	clang $(BPF_FLAGS) -c $< -o $@

bpf: $(BPF_OUTPUT)

build: $(GO_FILES)
	go build -o $(GO_OUTPUT) $(GO_FILES)
	ln proxy /usr/bin/witnessd

clean: 
	rm -f $(BPF_OUTPUT) $(GO_OUTPUT)
