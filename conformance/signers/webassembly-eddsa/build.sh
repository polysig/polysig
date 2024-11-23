#!/usr/bin/env bash

set -e

command -v wasm-pack "wasm-pack must be installed"

cd ../../../crates/bindings/webassembly
wasm-pack build \
	--target web \
	--features eddsa

cp -rf ./pkg ../../../conformance/signers/webassembly-eddsa/
