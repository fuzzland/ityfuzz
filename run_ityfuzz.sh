#!/bin/bash

# 执行 cargo build 命令
cargo build --release --features "cmp dataflow evm print_txn_corpus full_trace" --no-default-features

# 定义path变量
path="./tests/evm/flashloan"

# 执行ityfuzz命令
./target/release/ityfuzz evm -t "${path}/*" -f --panic-on-bug
