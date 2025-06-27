export RUST_LOG=debug
export AYA_LOG_LEVEL=debug
cargo run --release --config 'target."cfg(all())".runner="sudo -E"'