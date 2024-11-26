#!/usr/bin/env bash

set -e

cd ../../../
cargo run -- -b 127.0.0.1:8008 conformance/relay.toml
