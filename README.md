# ItyFuzz 🍦

Fast hybrid fuzzer for EVM & MoveVM (WIP) smart contracts.

You can generate exploits **instantly** by just providing the contract address:
![](https://ityfuzz.assets.fuzz.land/demo2.gif)

[Tool](https://github.com/fuzzland/ityfuzz/) / [Research Paper](https://scf.so/ityfuzz.pdf) / [Fuzzing EVM Contracts](#building-evm) / [Fuzzing Move Contracts](#building-with-move-sui-support)

### Run ItyFuzz with UI

Install [Docker](https://www.docker.com/) and run docker image suitable for your system architecture:

```
docker pull fuzzland/ityfuzz:stable
docker run -p 8000:8000 fuzzland/ityfuzz:stable
```

Then, you can visit the interface at http://localhost:8000

<sub>Note: The container uses public ETH RPC, may time out / be slow</sub>

### Statistics & Comparison

Time taken for finding vulnerabilities / generating exploits:

| Project Name  | Vulnerability           | **Mythril** | **SMARTIAN** | **Slither** | **ItyFuzz** |
| ------------- | ----------------------- | ----------- | ------------ | ----------- | ----------- |
| AES           | Business Logic          | Inf         | Unsupported  | No          | 4hrs        |
| Carrot        | Arbitrary External Call | 17s         | 11s          | Yes         | 1s          |
| Olympus       | Access Control          | 36s         | Inf          | Yes         | 1s          |
| MUMUG         | Price Manipulation      | Inf         | Unsupported  | No          | 18hrs       |
| Omni          | Reentrancy              | Inf         | Unsupported  | Yes\*       | 22hrs       |
| Verilog CTF-2 | Reentrancy              | Inf         | Unsupported  | Yes\*       | 3s          |

<sub>\* Slither only finds the reentrancy location, but not how to leverage reentrancy to trigger final buggy code. The output also contains significant amount of false positives. </sub>

Test Coverage:

| **Dataset** | **SMARTIAN** | **Echidna** | **ItyFuzz** |
| ----------- | ------------ | ----------- | ----------- |
| B1          | 97.1%        | 47.1%       | 99.2%       |
| B2          | 86.2%        | 82.9%       | 95.4%       |
| Tests       | Unsupported  | 52.9%       | 100%        |

<sub>\* B1 and B2 contain 72 single-contract projects from SMARTIAN artifacts. Tests are the projects in `tests` directory. The coverage is calculated as `(instruction covered) / (total instruction - dead code)`. </sub>


# Building (EVM)

You first need to install Rust through https://rustup.rs/

You need to have `libssl-dev` (OpenSSL) and `libz3-dev` (refer to [Z3 Installation](#z3-installation) section for instruction) installed.

```bash
git clone https://github.com/fuzzland/ityfuzz.git && cd ityfuzz && git checkout stable
git submodule update --recursive --init
cd cli/
cargo build --release
```

You can enable certain debug gates in `Cargo.toml`

`solc` is needed for compiling smart contracts. You can use `solc-select` tool to manage the version of `solc`.

# Run (EVM)

Compile Smart Contracts:

```bash
cd ./tests/evm/multi-contract/
# include the library from ./solidity_utils for example
solc *.sol -o . --bin --abi --overwrite --base-path ../../../
```

Run Fuzzer:

```bash
# after building, there should be a binary in ./cli/target/release/cli
cd ./cli/
./target/release/cli evm -t '../tests/evm/multi-contract/*'
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
# build contracts in tests/evm/verilog-2/
solc *.sol -o . --bin --abi --overwrite --base-path ../../../
# after building, there should be a binary in ./cli/target/release/cli

# run fuzzer 
cd ./cli/
./target/release/cli evm -f -t "../tests/evm/verilog-2/*"
```

`-f` flag enables automated flashloan, which hooks all ERC20 external calls and make any users to have infinite balance.

### Fuzz a Project (Offline)

You can fuzz a project by providing a path to the project directory.

```bash
./target/release/cli evm -t '[DIR_PATH]/*'
```

ItyFuzz would attempt to deploy all artifacts in the directory to a blockchain with no other smart contracts.

Specifically, the project directory should contain
a few `[X].abi` and `[X].bin` files. For example, to fuzz a contract named `main.sol`, you should
ensure `main.abi` and `main.bin` exist in the project directory.
The fuzzer will automatically detect the contracts in directory, the correlation between them (see `tests/evm/multi-contract`),
and fuzz them.

Optionally, if ItyFuzz fails to infer the correlation between contracts, you
can add a `[X].address`, where `[X]` is the contract name, to specify the address of the contract.

Caveats:

- Keep in mind that ItyFuzz is fuzzing on a clean blockchain,
  so you should ensure all related contracts (e.g., ERC20 token, Uniswap, etc.) are deployed to the blockchain before fuzzing.
- If your smart contract requires constructor arguments, please refer to below [Constructor Arguments](#constructor-arguments) section.

### Fuzz a Project (Online)

Rebuild with `flashloan_v2` (only supported in onchain) enabled to get better result.

```bash
python3 -c 'content=open("Cargo.toml").read().replace("default = [", "default = [\"flashloan_v2\",");open("Cargo.toml","w").write(content);'
cd ./cli/
cargo build --release
```

You can fuzz a project by providing an address, a block, and a chain type.

```bash
./target/release/cli evm -o -t [TARGET_ADDR] --onchain-block-number [BLOCK] -c [CHAIN_TYPE] --onchain-etherscan-api-key [Etherscan API Key]
```

Example:
Fuzzing WETH contract (`0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2`) on Ethereum mainnet at latest block.

```bash
./target/release/cli evm -o -t 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2 --onchain-block-number 0 -c ETH --onchain-etherscan-api-key PXUUKVEQ7Y4VCQYPQC2CEK4CAKF8SG7MVF
```

Fuzzing with flashloan and oracles enabled:

```bash
./target/release/cli evm -o -t 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2 --onchain-block-number 0 -c ETH -f -i -p --onchain-etherscan-api-key PXUUKVEQ7Y4VCQYPQC2CEK4CAKF8SG7MVF
```

ItyFuzz would pull the ABI of the contract from Etherscan and fuzz it.
If ItyFuzz encounters an unknown slot in the memory, it would pull the slot from chain RPC.
If ItyFuzz encounters calls to external unknown contract, it would pull the bytecode and ABI of that contract.
If its ABI is not available, ItyFuzz would not send any transaction to that contract.



### Constructor Arguments

ItyFuzz provides two methods to pass in constructor arguments. These arguments are necessary for initializing the state of the contract when deployed.

**Method 1: CLI Arguments**

The first method is to pass in the constructor arguments directly as CLI arguments.

When you run ItyFuzz using the CLI, you can include the `--constructor-args` flag followed by a string that specifies the arguments for each constructor.

The format is as follows:

```
./target/release/cli evm -t 'tests/evm/multi-contract/*' --constructor-args "ContractName:arg1,arg2,...;AnotherContract:arg1,arg2,..;"
```

For example, if you have two contracts, `main` and `main2`, both having a `bytes32` and a `uint256` as constructor arguments, you would pass them in like this:

```bash
./target/release/cli evm -t 'tests/evm/multi-contract/*' --constructor-args "main:1,0x6100000000000000000000000000000000000000000000000000000000000000;main2:2,0x6200000000000000000000000000000000000000000000000000000000000000;"
```

**Method 2: Server Forwarding**

The second method is to use our server to forward requests to a user-specified RPC, and cli will fetch the constructor arguments from the transactions sent to the RPC.

Firstly, go to the `/server` directory, and install the necessary packages:

```bash
cd /server
npm install
```

Then, start the server using the following command:

```bash
node app.js
```

By default, the server will forward requests to `http://localhost:8545`, which is the default address for [Ganache](https://github.com/trufflesuite/ganache), if you do not have a local blockchain running, you can use Ganache to start one.
If you wish to forward requests to another location, you can specify the address as a command-line argument like so:

```bash
node app.js http://localhost:8546
```

Once the server is running, you can deploy your contract to `localhost:5001` using a tool of your choice.

For example, you can use Foundry to deploy your contract through the server:

```bash
forge create src/flashloan.sol:main2 --rpc-url http://127.0.0.1:5001 --private-key 0x0000000000000000000000000000000000000000000000000000000000000000 --constructor-args "1" "0x6100000000000000000000000000000000000000000000000000000000000000"
```

Finally, you can fetch the constructor arguments using the `--fetch-tx-data` flag:

```bash
./target/release/cli evm -t 'tests/evm/multi-contract/*' --fetch-tx-data
```

ItyFuzz will fetch the constructor arguments from the transactions forwarded to the RPC through the server.

### Concolic Execution Support (Experimental)

Concolic execution can be performed on certain testcases on the fly during fuzzing. It is particularly useful for fuzzing code with complex
if-conditions. You can add `--concolic` to args to make fuzzer conduct concolic execution. You can also add `--concolic-caller` to args to make fuzzer solve for callers.

Example:
```
cd tests/evm/concolic-1/ && solc *.sol -o . --bin --abi --overwrite --base-path ../../../ && ../../../
./cli/target/release/cli evm -t 'tests/evm/concolic-1/*' --concolic --concolic-caller
```


# Finding Custom Bugs (EVM)

You can simply insert `bug()` or `typed_bug(string message)` in your contract to report a condition when bug is found.

For instance, a simple case can be written as follows:
```solidity
function buy_token() public {
    if (msg.sender != owner) {
        bug();
    }
}
```

The implementation of `bug()` is as follows:
```solidity
library FuzzLand {
    event AssertionFailed(string message);
  
    function bug() internal {
        emit AssertionFailed("Bug");
    }
  
    function typed_bug(string memory data) internal {
        emit AssertionFailed(data);
    }

}

function bug()  {
    FuzzLand.bug();
}

function typed_bug(string memory data)  {
    FuzzLand.typed_bug(data);
}
```

You can either paste the code above into your contract or import it from `solidity_utils/lib.sol`, if you are using `bug` or `typed_bug`.

### Echidna Support

Any contracts bearing functions starting with `echidna_` will be treated as invariants and will be tested by ItyFuzz.
If it returns `false`, the fuzzer will report a bug.

```solidity
function echidna_test() public {
    assert(false);
}
```


### Scribble Support

Scribble is a tool for writing specifications for Solidity contracts. ItyFuzz supports Scribble annotations after
it is compiled by `scribble`.

For example, the following contract has a Scribble annotation that specifies the return value of `inc`:
```bash
contract Foo {
    /// #if_succeeds {:msg "P1"} y == x + 2;
    function inc(uint x) public pure returns (uint y) {
        return x+1;
    }
}
```

You need to compile the contract using `scribble` and pass the compiled contract to ItyFuzz

Note that you must add `--no-assert` to the `scribble` command. Otherwise, ItyFuzz will not detect any bugs.
```bash
scribble test.sol --output-mode flat --output compiled.sol --no-assert
```

Then compile with `solc` and run ItyFuzz:
```bash
solc compiled.sol --bin --abi --overwrite -o build
./target/release/cli evm -t "build/*" [More Arguments]
```

# Test Coverage

ItyFuzz can collect instruction and branch coverage information for all the contracts it fuzzes. You simply
need to append `--replay-file [WORKDIR]/corpus/*_replayable` to collect all these information.
```bash
./target/release/cli evm -t [Targets] [Options Used During Fuzzing] --replay-file '[WORKDIR]/corpus/*_replayable'
```

Example:
```bash
./target/release/cli evm -t 'tests/evm/multi-contract/*' --replay-file 'work_dir/corpus/*_replayable'
```

You may add source map information to the targets to get more accurate coverage information and uncovered source code.
To get source map information, you simply need to append `--combined-json bin-runtime,srcmap-runtime` to the solc command when building the targets.
```bash
# run in your target building directory (where you run solc)
solc [Options Used During Building] --combined-json bin-runtime,srcmap-runtime 
```

Example:
```bash
# build contracts in tests/evm/verilog-2/
solc *.sol -o . --bin --abi --overwrite --base-path ../../ --combined-json bin-runtime,srcmap-runtime
```
Rarely, ItyFuzz has trouble to figure out the source code location.
You may supply the **absolute** path to the base location (what you passed to solc's --base-path or if you didn't pass anything, it is the building directory)
to ItyFuzz.
```bash
./target/release/cli evm -t [Targets] [Options Used During Fuzzing] --replay-file '[WORKDIR]/corpus/*_replayable' --base-path [ABSOLUTE PATH TO BASE LOCATION]
```

Example:
```bash
# note that we used --base-path ../../ when building the targets so it is /home/user/ityfuzz/tests/evm/verilog-2/../../
./target/release/cli evm -t 'tests/evm/multi-contract/*' --replay-file 'work_dir/corpus/*_replayable' --base-path /home/user/ityfuzz
```

We do not track coverage of static calls (view, pure functions) by default!

# Building With Move (Sui) Support
Build with feature `sui_support` in `./Cargo.toml` to enable Move support.

```bash
# add sui_support feature to Cargo.toml
python3 -c 'content=open("Cargo.toml").read().replace("default = [", "default = [\"sui_support\",");open("Cargo.toml","w").write(content);'

# build ItyFuzz with sui_support feature
cd cli/
cargo build --release
```

You may also want to install `sui-cli` to build Move contracts.

# Run (Move)
Compile the contracts with `sui move build` and run ItyFuzz:
```bash
# build example contract that contains a bug
cd ./tests/move/share_object
sui move build

# get back to ItyFuzz CLI and run fuzzing on the built contract
cd ../../../cli/
./target/release/cli move -t "./tests/move/share_object/build"
```

# Reporting Bugs (Move)
You can emit an event of `` in your contract to report a condition when bug is found.
```move
// define the event struct
use sui::event;

struct AAAA__fuzzland_move_bug has drop, copy, store {
    info: u64
}

... 
    // inside function
    event::emit(AAAA__fuzzland_move_bug { info: 1 });
...
```

An example contract that report a bug can be found in `tests/move/share_object/sources/test.move`.


# Troubleshooting
### Z3 Installation

**macOS**

```bash
git clone https://github.com/Z3Prover/z3 && cd z3
python scripts/mk_make.py --prefix=/usr/local
cd build && make -j64 && sudo make install
```

If the build command still fails for not finding `z3.h`, do `export Z3_SYS_Z3_HEADER=/usr/local/include/z3.h`

**Ubuntu**

```bash
apt install libz3-dev
```

### Onchain Fetching

ItyFuzz attempts to fetch storage from blockchain nodes when SLOAD is encountered and the target is uninitialized.
There are three ways of fetching:

- OneByOne: fetch one slot at a time. This is the default mode. It is slow but never fails.
- All: fetch all slots at once using custom API `eth_getStorageAll` on our nodes. This is the fastest mode, but it may fail if the contract is too large.
- Dump: dump storage using debug API `debug_storageRangeAt`. This only works for ETH (for now) and fails most of the time.

# Telemetry

ItyFuzz collects telemetry data to help us improve the fuzzer. The data is collected anonymously and is not used for any commercial purpose.
You can disable telemetry by setting `NO_TELEMETRY=1` in your environment variable.

# Citation
```
@inproceedings{10.1145/3597926.3598059,
  author = {Shou, Chaofan and Tan, Shangyin and Sen, Koushik},
  title = {ItyFuzz: Snapshot-Based Fuzzer for Smart Contract},
  year = {2023},
  isbn = {9798400702211},
  publisher = {Association for Computing Machinery},
  address = {New York, NY, USA},
  url = {https://doi.org/10.1145/3597926.3598059},
  doi = {10.1145/3597926.3598059},
  booktitle = {Proceedings of the 32nd ACM SIGSOFT International Symposium on Software Testing and Analysis},
  pages = {322–333},
  numpages = {12},
  location = {Seattle, WA, USA},
  series = {ISSTA 2023}
}
```

# Acknowledgement

This work was supported in part by NSF grants CCF-1900968, CCF1908870, and CNS1817122 and SKY Lab industrial sponsors and
affiliates Astronomer, Google, IBM, Intel, Lacework, Microsoft, Mohamed Bin Zayed University of Artificial Intelligence, Nexla, Samsung SDS, Uber, and VMware. Any opinions, findings, conclusions,
or recommendations in this repo do not necessarily reflect the position or the policy of the
sponsors.

Grants:
| Grants | Description |
|:----:|:-----------:|
| <img src=https://ityfuzz.assets.fuzz.land/sui.jpg width=100px/> | Grants from Sui Foundation for building Move and chain-specific support |
| <img src=https://ityfuzz.assets.fuzz.land/web3.png width=100px/> | Grants from Web3 Foundation for building Substrate pallets and Ink! support |
