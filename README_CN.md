# ItyFuzz 🍦

ItyFuzz 是一款快速的混合模糊测试工具，用于 EVM、MoveVM（WIP）等。

### 使用 UI 运行 ItyFuzz

安装 Docker，然后运行我们的 Docker 镜像（仅支持 x86，在非 x86 平台上运行会显著降低性能）：

```bash
docker run -p 8000:8000 fuzzland/ityfuzz
```

然后，您可以在 http://localhost:8000 访问 UI。

### 统计

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

# 开发

### 构建

您需要安装`libssl-dev`（OpenSSL）和`libz3-dev`。

```bash
# 下载依赖
git submodule update --recursive --init
cd cli/
cargo build --release
```

### 运行

编译智能合约：

```bash
cd ./tests/multi-contract/
solc *.sol -o . --bin --abi --overwrite --base-path ../../
```

运行 Fuzzer：

```bash
cd ./cli/
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
./cli -f -t "./tests/verilog-2/*"
```

`-f` 标志启用自动闪电贷款，它会 hook 所有 ERC20 外部调用，使任何用户都具有无限余额。

### 离线 Fuzz 一个项目

您可以通过提供项目目录的路径（glob）来 Fuzz 一个项目。

```bash
./cli -t '[DIR_PATH]/*'
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

- 您还需要覆盖智能合约中的所有`constructor(...)`使它没有参数。 ItyFuzz 假定构造函数没有参数。

### 在线 Fuzz 一个项目

（可选）启用 flashloan_v2 重新构建以获得更好的结果。

```bash
sed -i 's/\"default = [\"/\"default = [flashloan_v2,\"/g' ./Cargo.toml
cd ./cli/
cargo build --release
```

您可以通过提供地址，块和链来 fuzz 一个项目。

```bash
./cli -o -t [TARGET_ADDR] --onchain-block-number [BLOCK] -c [CHAIN_TYPE]
```

示例：
在以太坊主网最新区块上 fuzz WETH 合约（`0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2`）。

```bash
./cli -o -t 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2 --onchain-block-number 0 -c ETH
```

ItyFuzz 将从 Etherscan 拉取合约的 ABI 并 fuzz 它。如果 ItyFuzz 遇到 Storage 中未知的槽，它将从 RPC 同步槽。
如果 ItyFuzz 遇到对外部未知合约的调用，它将拉取该合约的字节码和 ABI。 如果它的 ABI 不可用，ItyFuzz 将使用 heimdall 对字节码进行反编译分析 ABI。
