#!/usr/bin/env bash

mkdir -p build

cd ../../../crates/bindings/node
npm run build:schnorr-debug

cp -f build/schnorr/debug/* ../../../conformance/signers/node-schnorr/build
