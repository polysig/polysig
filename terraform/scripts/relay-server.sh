#!/bin/bash
yum update -y
yum install -y curl
yum install -y gcc
sudo -u ec2-user -i <<'EOF'
ROOT=$(pwd)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. "$HOME/.cargo/env"
cargo install --git https://github.com/polysig/polysig.git polysig-server
polysig-keygen keypair -f server.pem
echo 'key = "server.pem"' > config.toml
echo '[cors]' >> config.toml
echo 'origins = ["https://tss.ac"]' >> config.toml
sudo $ROOT/.cargo/bin/polysig-relay config.toml --bind 0.0.0.0:80 &
EOF
