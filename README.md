# ItyFuzz
Fast hybrid fuzzer for EVM, MoveVM, etc.


### Building
```bash
cd cli/
cargo make build-cli
```

`solc` is needed for compiling smart contracts. You can use `solc-select` tool to manage the version of `solc`.

### Run
Compile Smart Contracts:
```bash
cd ./tests/multi-contract/
# include the library from ./solidity_utils for example
solc *.sol -o . --bin --abi --overwrite --base-path ../../
```
Run Fuzzer:
<!-- ```bash
cd cli/
cargo make --makefile cargo-make.toml run
```
or -->
```bash
# if cli binary exists
cd ./cli/
./cli --contract-glob '../tests/multi-contract/*'
```


### Z3 Installation (macOS)
```bash
git clone https://github.com/Z3Prover/z3 && cd z3
python scripts/mk_make.py --prefix=/usr/local
cd build && make -j64 && sudo make install
```
