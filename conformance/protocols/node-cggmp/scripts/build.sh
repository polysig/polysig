#!/usr/bin/env bash

set -e

mkdir -p build

cp ../../../conformance/ecdsa.json ./tests || echo "no test keys, run 'cargo make gen-keys'"

cd ../../../crates/bindings/node
npm run build-cggmp

cp -f build/cggmp/release/* ../../../conformance/protocols/node-cggmp/build/
