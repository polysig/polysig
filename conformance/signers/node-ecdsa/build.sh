#!/usr/bin/env bash

mkdir -p build

cd ../../../crates/bindings/node
npm run build:ecdsa-debug

cp -f build/ecdsa/debug/* ../../../conformance/signers/node-ecdsa/build
