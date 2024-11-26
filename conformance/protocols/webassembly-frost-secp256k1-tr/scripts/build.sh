#!/usr/bin/env bash

set -e

command -v wasm-pack "wasm-pack must be installed"

cp ../../../conformance/schnorr-serde.json ./tests || echo "no test keys, run 'cargo make gen-keys'"

cd ../../../crates/bindings/webassembly
wasm-pack build \
	--target web \
	--features frost-secp256k1-tr,tracing

cp -rf ./pkg ../../../conformance/protocols/webassembly-frost-secp256k1-tr/public/
