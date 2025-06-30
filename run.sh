export RUST_LOG=info
export AYA_LOG_LEVEL=info
export RUST_BACKTRACE=1
cargo run --release --config 'target."cfg(all())".runner="sudo -E"'