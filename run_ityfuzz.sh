#!/bin/bash


# 定义path变量
path="./tests/evm/flashloan"

# 执行 cargo build 命令
cargo build --release --features "cmp dataflow evm print_txn_corpus full_trace" --no-default-features

solc "${path}/test.sol" -o "${path}/" --bin --abi --overwrite --base-path "." --combined-json "bin-runtime,srcmap-runtime"



# 执行ityfuzz命令
./target/release/ityfuzz evm -t "${path}/*" -f --panic-on-bug
