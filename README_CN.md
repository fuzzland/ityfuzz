# ItyFuzz 🍦

ItyFuzz 是一款快速的混合模糊测试工具，用于 EVM、MoveVM（WIP）等。

只需提供合约地址，就能**立即**找到漏洞：
![](https://ityfuzz.assets.fuzz.land/demo2.gif)

[英文版 README](https://github.com/fuzzland/ityfuzz/blob/master/README.md) / [研究论文](https://scf.so/ityfuzz.pdf) / [开发信息](#development)


# 统计

发现漏洞/生成攻击所花费的时间：

| 项目名称      | 漏洞         | **Mythril** | **SMARTIAN** | **Slither** | **ItyFuzz** |
| ------------- | ------------ | ----------- | ------------ | ----------- | ----------- |
| AES           | 业务逻辑     | Inf         | 不支持       | No          | 4 小时      |
| Carrot        | 任意外部调用 | 17s         | 11s          | Yes         | 1s          |
| Olympus       | 访问控制     | 36s         | Inf          | Yes         | 1s          |
| MUMUG         | 价格操纵     | Inf         | 不支持       | No          | 18 小时     |
| Omni          | 重入         | Inf         | 不支持       | Yes\*       | 22 小时     |
| Verilog CTF-2 | 重入         | Inf         | 不支持       | Yes\*       | 3s          |

<sub>\* Slither 仅发现重入位置，而不是如何利用重入来触发最终的错误代码。输出还包含大量的误报。 </sub>

测试覆盖率：

| **数据集** | **SMARTIAN** | **Echidna** | **ItyFuzz** |
| ---------- | ------------ | ----------- | ----------- |
| B1         | 97.1%        | 47.1%       | 99.2%       |
| B2         | 86.2%        | 82.9%       | 95.4%       |
| Tests      | 不支持       | 52.9%       | 100%        |

<sub>\* B1 和 B2 包含 72 个合约。Tests 是 `tests` 目录中的项目。覆盖率计算为 `（覆盖的指令）/（总指令 - 无效代码）`。 </sub>

# 安装

## 1. ityfuzzup (推荐)

```bash
curl -L https://raw.githubusercontent.com/fuzzland/ityfuzz/master/ityfuzzup/install | bash
```

## 2. Release

下载最新的 [release](https://github.com/fuzzland/ityfuzz/releases/latest)

## 3. Docker

安装 [Docker](https://www.docker.com/) 并运行适用于你的系统架构的 docker 镜像：

```
docker pull fuzzland/ityfuzz:stable
docker run -p 8000:8000 fuzzland/ityfuzz:stable
```

然后，您可以在 http://localhost:8000 访问 UI。

<sub>注意：容器使用公共 ETH RPC，可能超时或运行缓慢</sub>

## 4. 从源码构建

您需要安装 `libssl-dev`（OpenSSL）和 `libz3-dev`（参见[Z3 安装](#z3-installation)章节中的说明）。

```bash
# 下载依赖
git submodule update --recursive --init
cargo build --release
```

你需要`solc`来编译智能合约。你可以使用`solc-select`工具来管理`solc`的版本。

# 运行

编译智能合约：

```bash
cd ./tests/multi-contract/
solc *.sol -o . --bin --abi --overwrite --base-path ../../
```

运行 Fuzzer：

```bash
./cli -t '../tests/multi-contract/*'
```

### Demo

**Verilog CTF Challenge 2**
`tests/verilog-2/`

合约有闪电贷款攻击+重入漏洞。攻击目标是到达`Bounty.sol`中的第 34 行。

具体漏洞利用过程：

```
0. 借k MATIC，使得 k > balance() / 10
1. 用k MATIC 调用 depositMATIC()
2. redeem(k * 1e18) --重入合约--> getBounty()
3. 返还k MATIC
```

使用 ItyFuzz 检测漏洞并生成具体漏洞利用过程（需要 0-200 秒）：

```bash
# 在tests/verilog-2/中构建合约
solc *.sol -o . --bin --abi --overwrite --base-path ../../
# 运行fuzzer
ityfuzz evm -f -t "../tests/evm/verilog-2/*"
```

`-f` 标志启用自动闪电贷款，它会 hook 所有 ERC20 外部调用，使任何用户都具有无限余额。

### 离线 Fuzz 一个项目

您可以通过提供项目目录的路径（glob）来 Fuzz 一个项目。

```bash
ityfuzz evm -t '[DIR_PATH]/*'
```

ItyFuzz 将尝试将目录中的所有工件部署到没有其他智能合约的区块链中。
项目目录中应当包含`[X].abi`和`[X].bin`文件。例如，要 fuzz 一个名为`main.sol`的合约，您应该
确保项目目录中存在`main.abi`和`main.bin`。
ItyFuzz 将自动检测目录中的合约之间的关联（参见`tests/multi-contract`），
并 fuzz 它们。

如果 ItyFuzz 无法推断合约之间的关联，您
也可以添加一个`[X].address`，其中`[X]`是合约名称，以指定合约的地址。

注意事项：

- ItyFuzz 在无任何合约的区块链上进行 fuzz，
  因此您应该确保在 fuzz 之前将所有相关合约（例如，ERC20 令牌，Uniswap 等）都将部署到 ItyFuzz 的区块链中。

### 在线 Fuzz 一个项目

Ityfuzz 将优先读取 `ETH_RPC_URL` 环境变量作为 RPC 地址，如果没有设置，将使用内置的公共 RPC 地址。


您可以通过提供地址，块和链来 fuzz 一个项目。

```bash
ityfuzz evm -o -t [TARGET_ADDR] --onchain-block-number [BLOCK] -c [CHAIN_TYPE] --onchain-etherscan-api-key [Etherscan API Key]
```

示例：
在以太坊主网最新区块上 fuzz WETH 合约（`0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2`）。

```bash
ityfuzz evm -o -t 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2 --onchain-block-number 0 -c ETH --onchain-etherscan-api-key PXUUKVEQ7Y4VCQYPQC2CEK4CAKF8SG7MVF
```

ItyFuzz 将从 Etherscan 拉取合约的 ABI 并 fuzz 它。如果 ItyFuzz 遇到 Storage 中未知的槽，它将从 RPC 同步槽。
如果 ItyFuzz 遇到对外部未知合约的调用，它将拉取该合约的字节码和 ABI。 如果它的 ABI 不可用，ItyFuzz 将使用 EVMole 对字节码进行反编译分析 ABI。

### Onchain 获取

当遇到 SLOAD 与目标未初始化的时，ItyFuzz 尝试从区块链节点获取存储。有三种获取方式：

- OneByOne：一次获取一个 slot 。这是默认模式。它很慢，但不会失败。
- Dump：使用 debug API `debug_storageRangeAt` 来转储存储。这只适用于 ETH（目前），并且很容易失败。

### 构造函数参数

ItyFuzz 提供两种方法来传入构造函数参数。这些参数对于在部署时初始化合约的状态是必要的。

**方法 1：CLI 参数**

第一种方法是直接作为 CLI 参数传入构造函数参数。

当你使用 CLI

运行 ItyFuzz 时，你可以包含`--constructor-args`标志，后跟一个指定每个构造函数的参数的字符串。

格式如下：

```
ityfuzz evm -t 'tests/evm/multi-contract/*' --constructor-args "ContractName:arg1,arg2,...;AnotherContract:arg1,arg2,..;"
```

例如，如果你有两个合约，`main` 和 `main2`，它们都有一个 `bytes32` 和一个 `uint256` 作为构造函数参数，你可以这样传入它们：

```bash
ityfuzz evm -t 'tests/evm/multi-contract/*' --constructor-args "main:1,0x6100000000000000000000000000000000000000000000000000000000000000;main2:2,0x6200000000000000000000000000000000000000000000000000000000000000;"
```

**方法 2：服务器转发**

第二种方法是使用我们的服务器将请求转发到用户指定的 RPC，cli 将从发送到 RPC 的交易中获取构造函数参数。

首先，进入`/server`目录，并安装必要的包：

```bash
cd /server
npm install
```

然后，使用以下命令启动服务器：

```bash
node app.js
```

默认情况下，服务器将请求转发到`http://localhost:8545`，这是[Ganache](https://github.com/trufflesuite/ganache)的默认地址，如果你没有运行本地区块链，你可以使用 Ganache 启动一个。
如果你希望将请求转发到其他位置，你可以像这样指定地址作为命令行参数：

```bash
node app.js http://localhost:8546
```

一旦服务器运行起来，你就可以使用你选择的工具将你的合约部署到 `localhost:5001`。

例如，你可以使用 Foundry 通过服务器部署你的合约：

```bash
forge create src/flashloan.sol:main2 --rpc-url http://127.0.0.1:5001 --private-key 0x0000000000000000000000000000000000000000000000000000000000000000 --constructor-args "1" "0x6100000000000000000000000000000000000000000000000000000000000000"
```

最后，你可以使用`--fetch-tx-data`标志获取构造函数参数：

```bash
ityfuzz evm -t 'tests/evm/multi-contract/*' --fetch-tx-data
```

ItyFuzz 将从通过服务器转发到 RPC 的交易中获取构造函数参数。

### Z3 安装

**macOS**

```bash
git clone https://github.com/Z3Prover/z3 && cd z3
python scripts/mk_make.py --prefix=/usr/local
cd build && make -j64 && sudo make install
```

如果构建命令仍然因找不到`z3.h`而失败，执行`export Z3_SYS_Z3_HEADER=/usr/local/include/z3.h`

或者你可以使用
```bash
brew install z3
```

**Ubuntu**

```bash
apt install libz3-dev
```

### Citation

```
@misc{ityfuzz,
      title={ItyFuzz: Snapshot-Based Fuzzer for Smart Contract},
      author={Chaofan Shou and Shangyin Tan and Koushik Sen},
      year={2023},
      eprint={2306.17135},
      archivePrefix={arXiv},
      primaryClass={cs.CR}
}
```
