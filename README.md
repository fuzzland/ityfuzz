# 🍦 ItyFuzz
![Demo](https://ityfuzz.assets.fuzz.land/demo-out.png)

[\[Docs\]](https://docs.ityfuzz.rs) /
[\[Research Paper\]](https://dl.acm.org/doi/pdf/10.1145/3597926.3598059) / 
[\[Twitter\]](https://twitter.com/fuzzland_) / 
[\[Discord\]](https://discord.com/invite/qQa436VEwt) / 
[\[Telegram\]](https://t.me/fuzzland) 



ItyFuzz is a blazing-fast EVM and MoveVM smart contract hybrid fuzzer that combines symbolic execution and fuzzing to find bugs in smart contracts offchain and onchain. 

## Install
```
curl -L https://ity.fuzz.land/ | bash
ityfuzzup
```

## Example
#### Fuzzing Deployed Smart Contract

Generating full exploit to steal funds from a [contract](https://polygonscan.com/address/0x5d6c48f05ad0fde3f64bab50628637d73b1eb0bb) with flashloan + read-only reentrancy vulnerability on Polygon.

```bash
# Fork Polygon at block 35718198 and fuzz the contract
ETH_RPC_URL=https://polygon-rpc.com ityfuzz evm\
    -t 0xbcf6e9d27bf95f3f5eddb93c38656d684317d5b4,0x5d6c48f05ad0fde3f64bab50628637d73b1eb0bb\
    -c polygon\
    --flashloan\
    --onchain-block-number 35718198\
    --onchain-etherscan-api-key TR24XDQF35QCNK9PZBV8XEH2XRSWTPWFWT # <-- Get your own API key at https://polygonscan.com/apis if this one is rate limited 
```

#### Foundry Invariant Test
Run a Foundry invariant test defined in `Invariant` contract in `test/Invariant.sol`.

```bash
# Replaces: forge test --mc test/Invariant.sol:Invariant
ityfuzz evm -m test/Invariant.sol:Invariant -- forge test
```

For other examples and usages, check out the [docs](https://docs.ityfuzz.rs).

## Performance
On large real-world smart contract projects, ItyFuzz finds 126 vulnerabilities while Echidna finds 0 and Mythril finds 9. For details, refer to [backtesting](https://docs.ityfuzz.rs/tutorials/exp-known-working-hacks), [research paper](https://dl.acm.org/doi/pdf/10.1145/3597926.3598059), and [new bugs discovered](#bugs-found).

On small real-world smart contracts (ERC20, lottery, etc.), ItyFuzz gains 10% more test coverage than academia state-of-the-art fuzzer SMARTIAN using 1/30 of the time.
<p align="middle">
    <img src="https://ityfuzz.assets.fuzz.land/ityfuzz3.png" width="49%">
    <img src="https://ityfuzz.assets.fuzz.land/ityfuzz1.png" width="49%">
</p>

On Consensys's [Daedaluzz](https://github.com/Consensys/daedaluzz) benchmark, ItyFuzz *without symbolic execution* finds 44% more bugs than Echidna and 31% more bugs than Foundry. ItyFuzz is also 2.5x faster than Echidna and 1.5x faster than Foundry.

<p align="middle">
    <img src="https://ityfuzz.assets.fuzz.land/daedaluzz-bar.jpeg" width="49%">
    <img src="https://ityfuzz.assets.fuzz.land/FvRIuhfWwAEdBBz.jpg" width="49%">
</p>

## Features

* **Chain forking** to fuzz contracts on any chain at any block number.
* **Accurate exploit generation** for precision loss, integer overflow, fund stealing, Uniswap pair misuse etc.
* **Reentrancy support** to concretely leverage potential reentrancy opportunities for exploring more code paths.
* **Blazing fast power scheduling** to prioritize fuzzing on code that is more likely to have bugs.
* **Symbolic execution** to generate test cases that cover more code paths than fuzzing alone.
* **Flashloan support** assuming attackers have infinite funds to exploit flashloan vulnerabilities.
* **Liquidation support** to simulate buying and selling any token from liquidity pools during fuzzing.
* **Decompilation support** for fuzzing contracts without source code.
* **Supports complex contracts initialization** using Foundry setup script, forking Anvil RPC, or providing a JSON config file.
* Backed by SOTA fuzzing engine [LibAFL](https://github.com/AFLplusplus/LibAFL).

## Bugs Found

Selected new vulnerabilities found:

| Project | Vulnerability | Assets at Risks |
| --- | --- | --- |
| BSC $rats NFT | Integer overflow leading to unlimited minting | $79k |
| 9419 Token | Incorrect logic leading to price manipulation | $35k |
| BSC Mevbot | Unguarded DPPFlashLoanCall | $19k |
| FreeCash | Incorrect logic leading to price manipulation | $12k |
| 0xnoob Token | Incorrect logic leading to price manipulation | $7k |
| Baby Wojak Token | Incorrect logic leading to price manipulation | $4k |
| Arrow | Incorrect position logic leading to fund loss | Found During Audit |

ItyFuzz can automatically generate exploits for >80% of previous hacks without any knowledge of the hack. 
Refer to [backtesting](https://docs.ityfuzz.rs/tutorials/exp-known-working-hacks) for running previously hacked protocols.


## Sponsors & Grants
* [Manifold Finance](https://www.manifoldfinance.com/)
* [Sui](https://sui.io/)
