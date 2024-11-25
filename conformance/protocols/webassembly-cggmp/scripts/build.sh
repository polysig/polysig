#!/usr/bin/env bash

set -e

command -v wasm-pack "wasm-pack must be installed"

cp ../../../conformance/ecdsa.json ./tests || echo "no test keys, run 'cargo make gen-keys'"

cd ../../../crates/bindings/webassembly
wasm-pack build \
	--target web \
	--features cggmp,tracing

cp -rf ./pkg ../../../conformance/protocols/webassembly-cggmp/public/
