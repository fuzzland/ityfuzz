# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ItyFuzz is a blazing-fast hybrid fuzzer for EVM and MoveVM smart contracts that combines symbolic execution and fuzzing to find vulnerabilities. Built on LibAFL, it supports both offchain contract fuzzing and onchain fuzzing with chain forking.

## Build & Development Commands

### Prerequisites
- Rust nightly toolchain (2024-01-01): Install via `rustup toolchain install nightly-2024-01-01`
- The project uses a specific nightly version defined in `rust-toolchain.toml`

### Building
```bash
# Standard build
cargo build --release

# Debug build
cargo build

# Build with specific features
cargo build --release --features "cmp dataflow evm print_txn_corpus full_trace"
```

### Running Tests
```bash
# Run all unit tests
cargo test --verbose

# Run integration tests (offchain only)
python3 integration_test.py offchain

# Run integration tests (onchain - requires RPC and Etherscan API keys)
python3 integration_test.py onchain

# Run single offchain test manually
./target/release/ityfuzz evm -t 'tests/evm/reentrancy/*' -f

# Run specific test with concolic execution
./target/release/ityfuzz evm -t 'tests/evm/concolic-1/*' --concolic --concolic-caller
```

### Code Quality
```bash
# Format check
cargo fmt -- --check

# Apply formatting
cargo fmt

# Lint (optional, commented out in CI)
cargo clippy --all-features
```

## Architecture

### Core Structure

The codebase is organized around a generic VM abstraction:

- **`src/generic_vm/`**: Generic traits for any VM implementation
  - `vm_executor.rs`: Executor trait abstraction
  - `vm_state.rs`: State management abstraction

- **`src/evm/`**: EVM-specific implementation (primary focus)
  - `vm.rs`: EVM execution engine built on `revm`
  - `host.rs`: Host environment for EVM execution
  - `input.rs`: EVM transaction input representation
  - `contract_utils.rs`: Contract deployment and initialization

- **`src/move/`**: MoveVM implementation (requires `sui_support` feature)

- **`src/fuzzers/`**: Fuzzer orchestration
  - `evm_fuzzer.rs`: Main EVM fuzzing logic
  - `move_fuzzer.rs`: MoveVM fuzzing logic

### Key Concepts

#### Middlewares (`src/evm/middlewares/`)
Middlewares are invoked for every opcode executed in REVM:
- **`coverage.rs`**: Instruction coverage tracking
- **`cheatcode/`**: Foundry cheatcode support for setup scripts
- **`reentrancy.rs`**: Reentrancy detection and exploitation
- **`sha3_bypass.rs`**: Symbolic SHA3 handling (enabled with `--sha3-bypass`)

#### Oracles (`src/evm/oracles/`)
Vulnerability detection modules:
- **`erc20.rs`**: ERC20 balance manipulation detection
- **`v2_pair.rs`**: Uniswap V2 pair price manipulation
- **`arb_call.rs`**: Arbitrary call detection
- **`reentrancy.rs`**: Reentrancy vulnerability oracle
- **`selfdestruct.rs`**: Selfdestruct vulnerabilities
- **`invariant.rs`**: Echidna-style invariant testing
- **`state_comp.rs`**: State comparison oracle
- **`typed_bug.rs`**: Type-specific bug patterns

#### Control Leak
When execution yields control to the caller mid-transaction (e.g., via external call), ItyFuzz saves the post-execution state. This enables fuzzing of reentrancy scenarios by continuing execution or injecting new transactions before the original transaction completes.

#### Onchain Support (`src/evm/onchain/`)
- **`endpoints.rs`**: Chain configuration and RPC endpoints
- Supports ETH, BSC, Polygon, Arbitrum, Optimism, Base, and many other chains
- Fetches bytecode and storage slots on-demand during fuzzing
- Requires chain-specific RPC URLs and Etherscan API keys

### Execution Flow

1. **Initialization**:
   - Parse CLI arguments (`src/evm/mod.rs` - `EvmArgs`)
   - Load contracts via `ContractLoader` (glob patterns, addresses, or Foundry setup)
   - Extract constants from bytecode via `bytecode_analyzer.rs`
   - Initialize corpus with default function calls

2. **Fuzzing Loop** (LibAFL-based):
   ```
   Input → REVM Execution → Outcome:
     - Reverted       → Discard
     - Control Leak   → Save post-execution state for reentrancy
     - Success        → Execute Producers → Run Oracles
   ```

3. **Feedback Collection** (`src/feedback.rs`):
   - Coverage feedback (branch, instruction)
   - Comparison feedback (CMP instructions for input generation)
   - State comparison feedback

4. **Scheduling** (`src/scheduler.rs`):
   - Infant scheduler: prioritizes recent interesting inputs
   - Power scheduling: allocates more fuzzing time to promising paths

## Feature Flags

Key features defined in `Cargo.toml`:

- **`evm`**: EVM support (default)
- **`cmp`**: Comparison feedback collection (default)
- **`dataflow`**: Dataflow analysis (default)
- **`print_txn_corpus`**: Print transaction corpus (default)
- **`full_trace`**: Full execution traces (default)
- **`force_cache`**: Force caching of onchain data (default)
- **`sui_support`**: Enable MoveVM/Sui support (optional)
- **`deployer_is_attacker`**: Treat deployer as attacker
- **`print_logs`**: Enable debug logging
- **`flashloan_debug`**: Debug flashloan logic
- **`no_etherscan`**: Disable Etherscan integration

## Common Workflows

### Fuzzing a Local Contract
```bash
# Compile Solidity contract
solc contracts/Target.sol -o out/ --bin --abi --overwrite

# Fuzz it
./target/release/ityfuzz evm -t 'out/*' -f
```

### Fuzzing Onchain Contracts
```bash
# Set RPC URL
export ETH_RPC_URL="https://eth.llamarpc.com"

# Fuzz deployed contract with flashloan
./target/release/ityfuzz evm \
  -t 0xTargetAddress \
  -c eth \
  -b 18000000 \
  --flashloan \
  --onchain-etherscan-api-key YOUR_KEY
```

### Foundry Invariant Testing
```bash
# Replace: forge test --mc test/Invariant.sol:Invariant
./target/release/ityfuzz evm -m test/Invariant.sol:Invariant -- forge test
```

## Dependencies

### Critical External Dependencies
- **`revm`**: Custom fork at `fuzzland/revm` - EVM execution engine with no gas metering and memory limits
- **`libafl` v0.11.2**: Fuzzing framework (exact version required)
- **`z3`**: SMT solver for symbolic execution (static-link-z3 feature)
- **`ethers`**: Ethereum utilities and RPC client
- **`foundry-cheatcodes`**: Foundry compatibility layer

### Move/Sui Dependencies (optional)
All Move-related crates are from `fuzzland/ityfuzz-sui-fork`, enabled only with `sui_support` feature.

## Important Notes

- The project requires Rust nightly with specific unstable features: `downcast_unchecked`, `let_chains`, `unchecked_math`, `trait_alias`
- Sentry error tracking is initialized by default (`init_sentry()` in `main.rs`)
- Git version info is embedded at build time via `build.rs`
- The `/cache` directory is populated from GitHub releases for integration tests
- Integration tests use `timeout`/`gtimeout` to prevent hangs (30s for offchain, 5m for onchain)
