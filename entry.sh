#!/bin/bash 

set -e 

sudo mount -t bpf none /sys/fs/bpf

mkdir ~/wittest
cd ~/wittest

openssl genpkey -algorithm ed25519 -outform PEM -out testkey.pem
openssl pkey -in testkey.pem -pubout > testpub.pem 

cat <<'EOF' > .witness.yaml
## .witness.yaml

run:
    signer-file-key-path: testkey.pem
    trace: false
verify:
    attestations:
        - "test-att.json"
    policy: policy-signed.json
    publickey: testpub.pem
EOF

git init

exec bash
