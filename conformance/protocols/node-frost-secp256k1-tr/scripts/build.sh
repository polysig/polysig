#!/usr/bin/env bash

set -e

mkdir -p build

cp ../../../conformance/schnorr.json ./tests || echo "no test keys, run 'cargo make gen-keys'"

cd ../../../crates/bindings/node
npm run build:frost-secp256k1-tr-debug

cp -f build/frost-secp256k1-tr/debug/* ../../../conformance/protocols/node-frost-secp256k1-tr/build/
