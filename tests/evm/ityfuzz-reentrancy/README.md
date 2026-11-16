# ItyFuzz Reentrancy Regression Test

This test checks whether ItyFuzz detects a deliberate reentrancy-style
invariant violation and whether a Checks-Effects-Interactions (CEI)
fix prevents that specific violation.

## Requirements

- Release binary: target/release/ityfuzz
- Solidity compiler: solc 0.8.20
- Bash and timeout

## Vulnerable fixture

Compile:

    mkdir -p tests/evm/ityfuzz-reentrancy/vulnerable-build

    solc --bin --abi --overwrite \
      --output-dir tests/evm/ityfuzz-reentrancy/vulnerable-build \
      tests/evm/ityfuzz-reentrancy/ReentrancyHarness.vulnerable.sol

Run:

    mkdir -p work_dir/ityfuzz-reentrancy

    timeout 180s ./target/release/ityfuzz evm \
      --target 'tests/evm/ityfuzz-reentrancy/vulnerable-build/*' \
      --target-type glob \
      --detectors all \
      --work-dir work_dir/ityfuzz-reentrancy \
      --seed 42

Expected: the deliberate Bug invariant violation is reported.

## Patched fixture

Compile:

    mkdir -p tests/evm/ityfuzz-reentrancy/patched-build

    solc --bin --abi --overwrite \
      --output-dir tests/evm/ityfuzz-reentrancy/patched-build \
      tests/evm/ityfuzz-reentrancy/ReentrancyHarness.sol

Run:

    mkdir -p work_dir/ityfuzz-reentrancy-patched

    timeout 180s ./target/release/ityfuzz evm \
      --target 'tests/evm/ityfuzz-reentrancy/patched-build/*' \
      --target-type glob \
      --detectors all \
      --work-dir work_dir/ityfuzz-reentrancy-patched \
      --seed 42

Expected: no Bug invariant violation during the 180-second run.
Exit code 124 is expected when timeout stops the fuzzer.

## Interpretation

The vulnerable fixture previously triggered the invariant violation.
The patched fixture completed the fuzzing window without reporting it.

This is a targeted regression test, not proof that the engine or
contract is free of all vulnerabilities.
