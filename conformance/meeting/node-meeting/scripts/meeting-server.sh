#!/usr/bin/env bash

cd ../../../
cargo run --bin polysig-meeting -- -b 127.0.0.1:8008 conformance/meeting.toml
