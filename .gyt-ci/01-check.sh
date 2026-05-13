#!/bin/sh
echo "Checking Rust toolchain..."
cargo --version && rustc --version
echo "OK"
