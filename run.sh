export RUST_LOG=debug
export AYA_LOG_LEVEL=debug
export RUST_BACKTRACE=1
cargo run --release --config 'target."cfg(all())".runner="sudo -E"'