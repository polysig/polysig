#!/usr/bin/env bash

set -e

command -v wasm-pack "wasm-pack must be installed"

cp ../../../conformance/ed25519.json ./tests || echo "no test keys, run 'cargo make gen-keys'"

cd ../../../crates/bindings/webassembly
wasm-pack build \
	--target web \
	--features frost-ed25519,tracing

cp -rf ./pkg ../../../conformance/protocols/webassembly-frost-ed25519/public/
