# ItyFuzz 🍦

ItyFuzz 是一款快速的混合模糊测试工具，用于 EVM、MoveVM（WIP）等。

### 使用 UI 运行 ItyFuzz
安装 Docker，然后运行我们的 Docker 镜像（仅支持 x86，在非 x86 平台上运行会显著降低性能）：

```bash
docker run -p 8000:8000 fuzzland/dev-ityfuzz-2
```

然后，您可以在 http://localhost:8000 访问UI。

### 统计

发现漏洞/生成攻击所花费的时间：

| 项目名称             | 漏洞           | **Mythril** | **SMARTIAN**    | **Slither** | **ItyFuzz** |
|---------------|-------------------------|---------|-------------|---------|---------|
| AES           | 业务逻辑          | Inf     | 不支持 | No      | 4小时    |
| Carrot        | 任意外部调用 | 17s     | 11s         | Yes     | 1s      |
| Olympus       | 访问控制          | 36s     | Inf         | Yes     | 1s      |
| MUMUG         | 价格操纵      | Inf     | 不支持         | No      | 18小时   |
| Omni          | 重入              | Inf     | 不支持         | Yes*    | 22小时   |
| Verilog CTF-2 | 重入              | Inf     | 不支持         | Yes*    | 3s      |

<sub>\* Slither 仅发现重入位置，而不是如何利用重入来触发最终的错误代码。输出还包含大量的误报。 </sub>

测试覆盖率：

| **数据集** | **SMARTIAN** | **Echidna** | **ItyFuzz** |
|-------------|--------------|-------------|-------------|
| B1          | 97.1%        | 47.1%       | 99.2%       |
| B2          | 86.2%        | 82.9%       | 95.4%       |
| Tests       | 不支持  | 52.9%       | 100%        |

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
运行Fuzzer：
```bash
cd ./cli/
./cli -t '../tests/multi-contract/*'
```

### Demo

**Verilog CTF Challenge 2**
`tests/verilog-2/`

合约有闪电贷款攻击+重入漏洞。攻击目标是到达`Bounty.sol`中的第34行。

具体漏洞利用过程：
```
0. 借k MATIC，使得 k > balance() / 10
1. 用k MATIC 调用 depositMATIC()
2. redeem(k * 1e18) --重入合约--> getBounty()
3. 返还k MATIC
```

使用ItyFuzz检测漏洞并生成具体漏洞利用过程（需要0-200秒）：
```bash
# 在tests/verilog-2/中构建合约
solc *.sol -o . --bin --abi --overwrite --base-path ../../
# 运行fuzzer
./cli -f -t "./tests/verilog-2/*"
```

`-f`标志启用自动闪电贷款，它会hook所有ERC20外部调用，使任何用户都具有无限余额。

### 离线Fuzz一个项目
您可以通过提供项目目录的路径（glob）来Fuzz一个项目。
```bash
./cli -t '[DIR_PATH]/*'
```
ItyFuzz将尝试将目录中的所有工件部署到没有其他智能合约的区块链中。
项目目录中应当包含`[X].abi`和`[X].bin`文件。例如，要fuzz一个名为`main.sol`的合约，您应该
确保项目目录中存在`main.abi`和`main.bin`。
ItyFuzz将自动检测目录中的合约之间的关联（参见`tests/multi-contract`），
并fuzz它们。

如果ItyFuzz无法推断合约之间的关联，您
也可以添加一个`[X].address`，其中`[X]`是合约名称，以指定合约的地址。

注意事项：

* ItyFuzz在无任何合约的区块链上进行fuzz，
因此您应该确保在fuzz之前将所有相关合约（例如，ERC20令牌，Uniswap等）都将部署到 ItyFuzz 的区块链中。

* 您还需要覆盖智能合约中的所有`constructor(...)`使它没有参数。 ItyFuzz假定构造函数没有参数。

### 在线Fuzz一个项目
您可以通过提供地址，块和链来fuzz一个项目。
```bash
./cli -o -t [TARGET_ADDR] --onchain-block-number [BLOCK] -c [CHAIN_TYPE] 
```

示例：
在以太坊主网最新区块上fuzz WETH合约（`0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2`）。
```bash
./cli -o -t 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2 --onchain-block-number 0 -c ETH
```

ItyFuzz将从Etherscan拉取合约的ABI并fuzz它。如果ItyFuzz遇到Storage中未知的槽，它将从RPC同步槽。
如果ItyFuzz遇到对外部未知合约的调用，它将拉取该合约的字节码和ABI。 如果它的ABI不可用，ItyFuzz将使用heimdall对字节码进行反编译分析ABI。

### 代理

为了有效地缓存昂贵的RPC调用，第三方API和Etherscan，我们创建了一个代理。 

运行代理：
```bash
cd onchain_scripts
python3 proxy.py
```

然后请将`--onchain-local-proxy-addr http://localhost:5003`附加到您的CLI命令中。 
