# ItyFuzz
Fast hybrid fuzzer for EVM, MoveVM, etc.


### Building
```bash
cd cli/
# download move dependencies
git submodule update --recursive --init
cargo build --release
```

If you encounter any Z3 related errors, please refer to [this](#z3-installation-macos) section.


You can enable certain debug gates in `Cargo.toml`


`solc` is needed for compiling smart contracts. You can use `solc-select` tool to manage the version of `solc`.


### Run
Compile Smart Contracts:
```bash
cd ./tests/multi-contract/
# include the library from ./solidity_utils for example
solc *.sol -o . --bin --abi --overwrite --base-path ../../
```
Run Fuzzer:
```bash
# if cli binary exists
cd ./cli/
./cli -t '../tests/multi-contract/*'
```


### Demo

**Verilog CTF Challenge 2**
`tests/verilog-2/`

Flashloan attack + Reentrancy. The target is to reach line 34 in `Bounty.sol`. 

Exact Exploit:
```
0. Borrow k MATIC such that k > balance() / 10
1. depositMATIC() with k MATIC
2. redeem(k * 1e18) -- reentrancy contract --> getBounty()
3. Return k MATIC
```

Use fuzzer to detect the vulnerability and generate the exploit (takes 0 - 200s):
```bash
# build contracts in tests/verilog-2/
solc *.sol -o . --bin --abi --overwrite --base-path ../../
# run fuzzer
./cli -f -t "./tests/verilog-2/*"
```

`-f` flag enables automated flashloan, which hooks all ERC20 external calls and make any users to have infinite balance. 

### Fuzz a Project (Offline)
You can fuzz a project by providing a path to the project directory. 
```bash
./cli -t '[DIR_PATH]/*'
```
ItyFuzz would attempt to deploy all artifacts in the directory to a blockchain with no other smart contracts.

Specifically, the project directory should contain 
a few `[X].abi` and `[X].bin` files. For example, to fuzz a contract named `main.sol`, you should
ensure `main.abi` and `main.bin` exist in the project directory.
The fuzzer will automatically detect the contracts in directory, the correlation between them (see `tests/multi-contract`),
and fuzz them.

Optionally, if ItyFuzz fails to infer the correlation between contracts, you
can add a `[X].address`, where `[X]` is the contract name, to specify the address of the contract.

Caveats:

* Keep in mind that ItyFuzz is fuzzing on a clean blockchain, 
so you should ensure all related contracts (e.g., ERC20 token, Uniswap, etc.) are deployed to the blockchain before fuzzing.

* You also need to overwrite all `constructor(...)` in the smart contract to 
to make it have no function argument. ItyFuzz assumes constructors have no argument.

### Fuzz a Project (Online)
You can fuzz a project by providing an address, a block, and a chain type.
```bash
./cli -o -t [TARGET_ADDR] --onchain-block-number [BLOCK] -c [CHAIN_TYPE] 
```

Example:
Fuzzing WETH contract (`0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2`) on Ethereum mainnet at latest block.
```bash
./cli -o -t 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2 --onchain-block-number 0 -c ETH
```

ItyFuzz would pull the ABI of the contract from Etherscan and fuzz it.
If ItyFuzz encounters an unknown slot in the memory, it would pull the slot from chain RPC.
If ItyFuzz encounters calls to external unknown contract, it would pull the bytecode and ABI of that contract. 
If its ABI is not available, ItyFuzz would not send any transaction to that contract.

### Z3 Installation (macOS)
```bash
git clone https://github.com/Z3Prover/z3 && cd z3
python scripts/mk_make.py --prefix=/usr/local
cd build && make -j64 && sudo make install
```
