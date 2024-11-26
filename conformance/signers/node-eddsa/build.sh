#!/usr/bin/env bash

set -e

mkdir -p build

cd ../../../crates/bindings/node
npm run build:eddsa-debug

cp -f build/eddsa/debug/* ../../../conformance/signers/node-eddsa/build
