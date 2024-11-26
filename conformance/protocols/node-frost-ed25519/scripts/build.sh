#!/usr/bin/env bash

set -e

mkdir -p build

cp ../../../conformance/ed25519.json ./tests || echo "no test keys, run 'cargo make gen-keys'"

cd ../../../crates/bindings/node
npm run build:frost-ed25519-debug

cp -f build/frost-ed25519/debug/* ../../../conformance/protocols/node-frost-ed25519/build/
