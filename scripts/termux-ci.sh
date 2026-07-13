#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

# Run the suite natively under Android/Bionic, then exercise the shipped CLI
# against the public fixture tree rather than stopping at compile coverage.
pkg update -y
pkg install -y git rust
export CARGO_BUILD_JOBS=1
export RUST_MIN_STACK=33554432
cargo test --locked --lib
cargo run --locked --bin grafhome-ca -- check --config-root examples/site-config
