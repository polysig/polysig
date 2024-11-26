#!/usr/bin/env bash

set -e

mkdir -p build

cp ../../../conformance/ecdsa.json ./tests || echo "no test keys, run 'cargo make gen-keys'"

cd ../../../crates/bindings/node
npm run build:cggmp-debug

cp -f build/cggmp/debug/* ../../../conformance/protocols/node-cggmp/build/
