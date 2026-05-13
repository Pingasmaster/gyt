#!/bin/sh
echo "Building..."
cargo build --all-features 2>&1
echo "BUILD OK"
