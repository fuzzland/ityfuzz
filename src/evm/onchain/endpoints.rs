use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    env,
    fmt::Debug,
    hash::{Hash, Hasher},
    io::{Read, Write},
    os::unix::net::UnixStream,
    panic,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Result};
use bytes::Bytes;
use reqwest::{blocking, header::HeaderMap};
use retry::{delay::Fixed, retry_with_index, OperationResult};
use revm_interpreter::analysis::to_analysed;
use revm_primitives::{Bytecode, B160};
use serde::Deserialize;
use serde_json::{json, Value};
use tracing::{debug, error, info, warn};

use super::ChainConfig;
use crate::{
    cache::{Cache, FileSystemCache},
    evm::{
        tokens::TokenContext,
        types::{EVMAddress, EVMU256},
    },
};

#[derive(Clone, Debug, Hash, PartialEq, Eq, Copy)]
pub enum Chain {
    ETH,
    GOERLI,
    SEPOLIA,
    BSC,
    CHAPEL,
    POLYGON,
    MUMBAI,
    FANTOM,
    AVALANCHE,
    OPTIMISM,
    ARBITRUM,
    GNOSIS,
    BASE,
    CELO,
    ZKEVM,
    ZkevmTestnet,
    BLAST,
    LINEA,
    LOCAL,
    IOTEX,
    SCROLL,
    VANA,
}

pub trait PriceOracle: Debug {
    // ret0: price = int(original_price x 10^5)
    // ret1: decimals of the token
    fn fetch_token_price(&mut self, token_address: EVMAddress) -> Option<(u32, u32)>;
}

impl FromStr for Chain {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "eth" | "mainnet" => Ok(Self::ETH),
            "goerli" => Ok(Self::GOERLI),
            "sepolia" => Ok(Self::SEPOLIA),
            "bsc" => Ok(Self::BSC),
            "chapel" => Ok(Self::CHAPEL),
            "polygon" => Ok(Self::POLYGON),
            "mumbai" => Ok(Self::MUMBAI),
            "fantom" => Ok(Self::FANTOM),
            "avalanche" => Ok(Self::AVALANCHE),
            "optimism" => Ok(Self::OPTIMISM),
            "arbitrum" => Ok(Self::ARBITRUM),
            "gnosis" => Ok(Self::GNOSIS),
            "base" => Ok(Self::BASE),
            "celo" => Ok(Self::CELO),
            "zkevm" => Ok(Self::ZKEVM),
            "zkevm_testnet" => Ok(Self::ZkevmTestnet),
            "blast" => Ok(Self::BLAST),
            "linea" => Ok(Self::LINEA),
            "local" => Ok(Self::LOCAL),
            "iotex" => Ok(Self::IOTEX),
            "scroll" => Ok(Self::SCROLL),
            "vana" => Ok(Self::VANA),
            _ => Err(()),
        }
    }
}

impl Chain {
    pub fn new_with_rpc_url(rpc_url: &str) -> Result<Self> {
        let client = blocking::Client::new();
        let body = json!({
            "method": "eth_chainId",
            "params": [],
            "id": 1,
            "jsonrpc": "2.0"
        })
        .to_string();

        let resp: Value = if rpc_url.starts_with("http://") || rpc_url.starts_with("https://") {
            // HTTP request
            let response = client
                .post(rpc_url)
                .header("Content-Type", "application/json")
                .body(body.clone())
                .send()?;
            response.json::<Value>()?
        } else if rpc_url.starts_with("/") || rpc_url.starts_with("./") || rpc_url.starts_with("../") {
            // IPC request
            let mut stream = UnixStream::connect(rpc_url)?;
            stream.write_all(body.as_bytes())?;

            let mut response = String::new();
            stream.read_to_string(&mut response)?;
            serde_json::from_str(&response)?
        } else {
            return Err(anyhow!("Unsupported URL scheme: {}", rpc_url));
        };

        let chain_id = resp
            .get("result")
            .and_then(|result| result.as_str())
            .and_then(|result| u64::from_str_radix(result.trim_start_matches("0x"), 16).ok())
            .ok_or_else(|| anyhow!("Failed to parse chain id from response: {}", rpc_url))?;

        env::set_var("ETH_RPC_URL", rpc_url);

        Ok(match chain_id {
            1 => Self::ETH,
            5 => Self::GOERLI,
            11155111 => Self::SEPOLIA,
            56 => Self::BSC,
            97 => Self::CHAPEL,
            137 => Self::POLYGON,
            80001 => Self::MUMBAI,
            250 => Self::FANTOM,
            43114 => Self::AVALANCHE,
            10 => Self::OPTIMISM,
            42161 => Self::ARBITRUM,
            100 => Self::GNOSIS,
            8453 => Self::BASE,
            42220 => Self::CELO,
            1101 => Self::ZKEVM,
            1442 => Self::ZkevmTestnet,
            81457 => Self::BLAST,
            59144 => Self::LINEA,
            4689 => Self::IOTEX,
            534352 => Self::SCROLL,
            1480 => Self::VANA,
            31337 => Self::LOCAL,
            _ => return Err(anyhow!("Unknown chain id: {}", chain_id)),
        })
    }

    pub fn get_chain_id(&self) -> u32 {
        match self {
            Chain::ETH => 1,
            Chain::GOERLI => 5,
            Chain::SEPOLIA => 11155111,
            Chain::BSC => 56,
            Chain::CHAPEL => 97,
            Chain::POLYGON => 137,
            Chain::MUMBAI => 80001,
            Chain::FANTOM => 250,
            Chain::AVALANCHE => 43114,
            Chain::OPTIMISM => 10,
            Chain::ARBITRUM => 42161,
            Chain::GNOSIS => 100,
            Chain::BASE => 8453,
            Chain::CELO => 42220,
            Chain::ZKEVM => 1101,
            Chain::ZkevmTestnet => 1442,
            Chain::BLAST => 81457,
            Chain::LINEA => 59144,
            Chain::IOTEX => 4689,
            Chain::SCROLL => 534352,
            Chain::VANA => 1480,
            Chain::LOCAL => 31337,
        }
    }

    pub fn to_lowercase(&self) -> String {
        match self {
            Chain::ETH => "eth",
            Chain::GOERLI => "goerli",
            Chain::SEPOLIA => "sepolia",
            Chain::BSC => "bsc",
            Chain::CHAPEL => "chapel",
            Chain::POLYGON => "polygon",
            Chain::MUMBAI => "mumbai",
            Chain::FANTOM => "fantom",
            Chain::AVALANCHE => "avalanche",
            Chain::OPTIMISM => "optimism",
            Chain::ARBITRUM => "arbitrum",
            Chain::GNOSIS => "gnosis",
            Chain::BASE => "base",
            Chain::CELO => "celo",
            Chain::ZKEVM => "zkevm",
            Chain::ZkevmTestnet => "zkevm_testnet",
            Chain::BLAST => "blast",
            Chain::LINEA => "linea",
            Chain::LOCAL => "local",
            Chain::IOTEX => "iotex",
            Chain::SCROLL => "scroll",
            Chain::VANA => "vana",
        }
        .to_string()
    }

    pub fn get_chain_rpc(&self) -> String {
        if let Ok(url) = env::var("ETH_RPC_URL") {
            return url;
        }
        match self {
            Chain::ETH => "https://eth.merkle.io",
            Chain::GOERLI => "https://rpc.ankr.com/eth_goerli",
            Chain::SEPOLIA => "https://rpc.ankr.com/eth_sepolia",
            Chain::BSC => "https://bnb.api.onfinality.io/public",
            Chain::CHAPEL => "https://rpc.ankr.com/bsc_testnet_chapel",
            Chain::POLYGON => "https://polygon.llamarpc.com",
            Chain::MUMBAI => "https://rpc-mumbai.maticvigil.com/",
            Chain::FANTOM => "https://rpc.ankr.com/fantom",
            Chain::AVALANCHE => "https://rpc.ankr.com/avalanche",
            Chain::OPTIMISM => "https://rpc.ankr.com/optimism",
            Chain::ARBITRUM => "https://rpc.ankr.com/arbitrum",
            Chain::GNOSIS => "https://rpc.ankr.com/gnosis",
            Chain::BASE => "https://developer-access-mainnet.base.org",
            Chain::CELO => "https://rpc.ankr.com/celo",
            Chain::ZKEVM => "https://rpc.ankr.com/polygon_zkevm",
            Chain::ZkevmTestnet => "https://rpc.ankr.com/polygon_zkevm_testnet",
            Chain::BLAST => "https://rpc.ankr.com/blast",
            Chain::LINEA => "https://rpc.ankr.com/linea",
            Chain::IOTEX => "https://rpc.ankr.com/iotex",
            Chain::SCROLL => "https://rpc.ankr.com/scroll",
            Chain::VANA => "https://rpc.vana.org",
            Chain::LOCAL => "http://localhost:8545",
        }
        .to_string()
    }

    pub fn get_chain_etherscan_base(&self) -> String {
        match self {
            Chain::ETH => "https://api.etherscan.io/api",
            Chain::GOERLI => "https://api-goerli.etherscan.io/api",
            Chain::SEPOLIA => "https://api-sepolia.etherscan.io/api",
            Chain::BSC => "https://api.bscscan.com/api",
            Chain::CHAPEL => "https://api-testnet.bscscan.com/api",
            Chain::POLYGON => "https://api.polygonscan.com/api",
            Chain::MUMBAI => "https://mumbai.polygonscan.com/api",
            Chain::FANTOM => "https://api.ftmscan.com/api",
            Chain::AVALANCHE => "https://api.snowtrace.io/api",
            Chain::OPTIMISM => "https://api-optimistic.etherscan.io/api",
            Chain::ARBITRUM => "https://api.arbiscan.io/api",
            Chain::GNOSIS => "https://api.gnosisscan.io/api",
            Chain::BASE => "https://api.basescan.org/api",
            Chain::CELO => "https://api.celoscan.io/api",
            Chain::ZKEVM => "https://api-zkevm.polygonscan.com/api",
            Chain::ZkevmTestnet => "https://api-testnet-zkevm.polygonscan.com/api",
            Chain::BLAST => "https://api.routescan.io/v2/network/mainnet/evm/81457/etherscan",
            Chain::LINEA => "https://api.lineascan.build/api",
            Chain::LOCAL => "http://localhost:8080/abi/",
            Chain::IOTEX => "https://babel-api.mainnet.IoTeX.io",
            Chain::SCROLL => "https://api.scrollscan.com/api",
            Chain::VANA => "https://api.vanascan.io/api/v2",
        }
        .to_string()
    }
}

#[derive(Clone, Debug, Default)]
pub struct PairData {
    pub src: String,
    pub in_: i32,
    pub pair: String,
    pub in_token: String,
    pub next: String,
    pub interface: String,
    pub src_exact: String,
    pub initial_reserves_0: EVMU256,
    pub initial_reserves_1: EVMU256,
    pub decimals_0: u32,
    pub decimals_1: u32,
    pub token0: String,
    pub token1: String,
}

#[derive(Deserialize)]
pub struct GetPairResponse {
    pub data: GetPairResponseData,
}

#[derive(Deserialize)]
pub struct GetPairResponseData {
    pub p0: Vec<GetPairResponseDataPair>,
    pub p1: Vec<GetPairResponseDataPair>,
}

#[derive(Deserialize)]
pub struct GetPairResponseDataPair {
    pub id: String,
    pub token0: GetPairResponseDataPairToken,
    pub token1: GetPairResponseDataPairToken,
}

#[derive(Deserialize)]
pub struct GetPairResponseDataPairToken {
    pub decimals: String,
    pub id: String,
}

#[derive(Clone, Default)]
pub struct OnChainConfig {
    pub endpoint_url: String,
    pub client: reqwest::blocking::Client,
    pub chain_id: u32,
    pub block_number: String,
    pub timestamp: Option<String>,
    pub coinbase: Option<String>,
    pub gaslimit: Option<String>,
    pub block_hash: Option<String>,

    pub etherscan_api_key: Vec<String>,
    pub etherscan_base: String,

    pub chain_name: String,

    balance_cache: HashMap<EVMAddress, EVMU256>,
    pair_cache: HashMap<EVMAddress, Vec<PairData>>,
    slot_cache: HashMap<(EVMAddress, EVMU256), EVMU256>,
    code_cache: HashMap<EVMAddress, String>,
    code_cache_analyzed: HashMap<EVMAddress, Bytecode>,
    price_cache: HashMap<EVMAddress, Option<(u32, u32)>>,
    abi_cache: HashMap<EVMAddress, Option<String>>,
    storage_dump_cache: HashMap<EVMAddress, Option<Arc<HashMap<EVMU256, EVMU256>>>>,
    uniswap_path_cache: HashMap<EVMAddress, TokenContext>,
    rpc_cache: FileSystemCache,
}

impl Debug for OnChainConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnChainConfig")
            .field("endpoint_url", &self.endpoint_url)
            .field("chain_id", &self.chain_id)
            .field("block_number", &self.block_number)
            .field("timestamp", &self.timestamp)
            .field("coinbase", &self.coinbase)
            .field("gaslimit", &self.gaslimit)
            .field("block_hash", &self.block_hash)
            .field("etherscan_api_key", &self.etherscan_api_key)
            .field("etherscan_base", &self.etherscan_base)
            .field("chain_name", &self.chain_name)
            .field("balance_cache", &self.balance_cache)
            .field("pair_cache", &self.pair_cache)
            .field("slot_cache", &self.slot_cache)
            .field("code_cache", &self.code_cache)
            .field("price_cache", &self.price_cache)
            .field("abi_cache", &self.abi_cache)
            .field("storage_dump_cache", &self.storage_dump_cache)
            .field("uniswap_path_cache", &self.uniswap_path_cache)
            .field("rpc_cache", &self.rpc_cache)
            .finish()
    }
}

impl ChainConfig for OnChainConfig {
    fn get_pair(&mut self, token: &str, is_pegged: bool) -> Vec<PairData> {
        let network = self.chain_name.clone();
        let weth = self.get_weth();
        self.get_pair(token, &network, is_pegged, weth)
    }

    fn fetch_reserve(&self, pair: &str) -> Option<(String, String)> {
        self.fetch_reserve(pair)
    }

    fn get_contract_code_analyzed(&mut self, address: EVMAddress, force_cache: bool) -> Bytecode {
        self.get_contract_code_analyzed(address, force_cache)
    }

    fn get_v3_fee(&mut self, address: EVMAddress) -> u32 {
        self.get_v3_fee(address)
    }

    fn get_token_balance(&mut self, token: EVMAddress, address: EVMAddress) -> EVMU256 {
        self.get_token_balance(token, address)
    }

    fn get_weth(&self) -> String {
        let pegged_token = self.get_pegged_token();

        match self.chain_name.as_str() {
            "eth" | "arbitrum" | "scroll" => return pegged_token.get("WETH").unwrap().to_string(),
            "bsc" => return pegged_token.get("WBNB").unwrap().to_string(),
            "polygon" => return pegged_token.get("WMATIC").unwrap().to_string(),
            "vana" => return pegged_token.get("WVANA").unwrap().to_string(),
            "local" => return pegged_token.get("ZERO").unwrap().to_string(),
            // "mumbai" => panic!("Not supported"),
            _ => {
                warn!("Unknown network");
                "".to_string()
            }
        }
    }

    fn get_pegged_token(&self) -> HashMap<String, String> {
        match self.chain_name.as_str() {
            "eth" => [
                ("WETH", "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"),
                ("USDC", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
                ("USDT", "0xdac17f958d2ee523a2206206994597c13d831ec7"),
                ("DAI", "0x6b175474e89094c44da98b954eedeac495271d0f"),
                ("WBTC", "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599"),
                ("WMATIC", "0x7d1afa7b718fb893db30a3abc0cfc608aacfebb0"),
            ]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
            "bsc" => [
                ("WBNB", "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c"),
                ("USDC", "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d"),
                ("USDT", "0x55d398326f99059ff775485246999027b3197955"),
                ("DAI", "0x1af3f329e8be154074d8769d1ffa4ee058b1dbc3"),
                ("WBTC", "0x7130d2a12b9bcbfae4f2634d864a1ee1ce3ead9c"),
                ("WETH", "0x2170ed0880ac9a755fd29b2688956bd959f933f8"),
                ("BUSD", "0xe9e7cea3dedca5984780bafc599bd69add087d56"),
                ("CAKE", "0x0e09fabb73bd3ade0a17ecc321fd13a19e81ce82"),
            ]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
            "polygon" => [
                ("WMATIC", "0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270"),
                ("USDC", "0x2791bca1f2de4661ed88a30c99a7a9449aa84174"),
                ("USDT", "0xc2132d05d31c914a87c6611c10748aeb04b58e8f"),
                ("DAI", "0x8f3cf7ad23cd3cadbd9735aff958023239c6a063"),
                ("WBTC", "0x1bfd67037b42cf73acf2047067bd4f2c47d9bfd6"),
                ("WETH", "0x7ceb23fd6bc0add59e62ac25578270cff1b9f619"),
            ]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
            "arbitrum" => [
                ("WETH", "0x82af49447d8a07e3bd95bd0d56f35241523fbab1"),
                ("WBTC", "0x2f2a2543b76a4166549f7aab2e75bef0aefc5b0f"),
                ("USDT", "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9"),
                ("USDC.e", "0xff970a61a04b1ca14834a43f5de4533ebddb5cc8"),
                ("USDC", "0xaf88d065e77c8cc2239327c5edb3a432268e5831"),
                ("DAI", "0xda10009cbd5d07dd0cecc66161fc93d7c9000da1"),
                ("crvUSD", "0x498bf2b1e120fed3ad3d42ea2165e9b73f99c1e5"),
            ]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
            "scroll" => [
                ("WETH", "0x5300000000000000000000000000000000000004"),
                ("WBTC", "0x3C1BCa5a656e69edCD0D4E36BEbb3FcDAcA60Cf1"),
                ("USDT", "0xf55BEC9cafDbE8730f096Aa55dad6D22d44099Df"),
                ("USDC", "0x06eFdBFf2a14a7c8E15944D1F4A48F9F95F663A4"),
                ("DAI", "0xcA77eB3fEFe3725Dc33bccB54eDEFc3D9f764f97"),
            ]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
            "vana" => [
                ("WETH", "0x2F6F07CDcf3588944Bf4C42aC74ff24bF56e7590"),
                ("USDC.e", "0xF1815bd50389c46847f0Bda824eC8da914045D14"),
                ("WVANA", "0x00EDdD9621Fb08436d0331c149D1690909a5906d"),
            ]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
            "local" => [("ZERO", "0x0000000000000000000000000000000000000000")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            _ => {
                warn!("[Flashloan] Network is not supported");
                HashMap::new()
            }
        }
    }
}

impl OnChainConfig {
    pub fn new(chain: Chain, block_number: u64) -> Self {
        Self::new_raw(
            chain.get_chain_rpc(),
            chain.get_chain_id(),
            block_number,
            chain.get_chain_etherscan_base(),
            chain.to_lowercase(),
        )
    }

    pub fn new_raw(
        endpoint_url: String,
        chain_id: u32,
        block_number: u64,
        etherscan_base: String,
        chain_name: String,
    ) -> Self {
        let mut s = Self {
            endpoint_url,
            client: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(20))
                .build()
                .expect("build client failed"),
            chain_id,
            block_number: format!("0x{:x}", block_number),
            timestamp: None,
            coinbase: None,
            gaslimit: None,
            block_hash: None,
            etherscan_api_key: vec![],
            etherscan_base,
            chain_name,
            rpc_cache: FileSystemCache::new("./cache"),
            ..Default::default()
        };
        if block_number == 0 {
            s.set_latest_block_number();
        }
        s
    }

    fn get(&self, url: String) -> Option<String> {
        let mut hasher = DefaultHasher::new();
        let key = format!("get_{}", url.as_str());
        key.hash(&mut hasher);
        let hash = hasher.finish().to_string();
        if let Ok(t) = self.rpc_cache.load(hash.as_str()) {
            return Some(t);
        }
        match retry_with_index(Fixed::from_millis(1000), |current_try| {
            if current_try > 5 {
                return OperationResult::Err("did not succeed within 3 tries".to_string());
            }
            match self.client.get(url.to_string()).headers(get_header()).send() {
                Ok(resp) => {
                    let text = resp.text();
                    match text {
                        Ok(t) => {
                            if t.contains("Max rate limit reached") {
                                debug!("Etherscan max rate limit reached, retrying...");
                                OperationResult::Retry("Rate limit reached".to_string())
                            } else {
                                OperationResult::Ok(t)
                            }
                        }
                        Err(e) => {
                            error!("{:?}", e);
                            OperationResult::Retry("failed to parse response".to_string())
                        }
                    }
                }
                Err(e) => {
                    error!("Error: {}", e);
                    OperationResult::Retry("failed to send request".to_string())
                }
            }
        }) {
            Ok(t) => {
                if !t.contains("error") {
                    self.rpc_cache.save(hash.as_str(), t.as_str()).unwrap();
                }

                Some(t)
            }
            Err(e) => {
                error!("Error: {}", e);
                None
            }
        }
    }

    fn post(&self, url: String, data: String) -> Option<String> {
        let mut hasher = DefaultHasher::new();
        let key = format!("post_{}_{}", url.as_str(), data.as_str());
        key.hash(&mut hasher);
        let hash = hasher.finish().to_string();
        if let Ok(t) = self.rpc_cache.load(hash.as_str()) {
            return Some(t);
        }
        match retry_with_index(Fixed::from_millis(100), |current_try| {
            if current_try > 3 {
                return OperationResult::Err("did not succeed within 3 tries".to_string());
            }
            match self
                .client
                .post(url.to_string())
                .header("Content-Type", "application/json")
                .headers(get_header())
                .body(data.to_string())
                .send()
            {
                Ok(resp) => {
                    let text = resp.text();
                    match text {
                        Ok(t) => OperationResult::Ok(t),
                        Err(e) => {
                            error!("{:?}", e);
                            OperationResult::Retry("failed to parse response".to_string())
                        }
                    }
                }
                Err(e) => {
                    error!("Error: {}", e);
                    OperationResult::Retry("failed to send request".to_string())
                }
            }
        }) {
            Ok(t) => {
                if !t.contains("error") {
                    self.rpc_cache.save(hash.as_str(), t.as_str()).unwrap();
                }
                Some(t)
            }
            Err(e) => {
                error!("Error: {}", e);
                None
            }
        }
    }

    pub fn set_latest_block_number(&mut self) {
        let resp = self._request("eth_blockNumber".to_string(), "[]".to_string());
        match resp {
            Some(resp) => {
                let block_number = resp.as_str().unwrap();
                self.block_number = block_number.to_string();
                let block_number = EVMU256::from_str_radix(block_number.trim_start_matches("0x"), 16)
                    .unwrap()
                    .to_string();
                debug!("latest block number is {}", block_number);
            }
            None => panic!("fail to get latest block number"),
        }
    }

    pub fn add_etherscan_api_key(&mut self, key: String) {
        self.etherscan_api_key.push(key);
    }

    pub fn fetch_blk_hash(&mut self) -> &String {
        if self.block_hash.is_none() {
            self.block_hash = {
                let mut params = String::from("[");
                params.push_str(&format!("\"{}\",false", self.block_number));
                params.push(']');
                let res = self._request("eth_getBlockByNumber".to_string(), params);
                match res {
                    Some(res) => {
                        let blk_hash = res["hash"].as_str().expect("fail to find block hash").to_string();
                        Some(blk_hash)
                    }
                    None => panic!("fail to get block hash"),
                }
            }
        }
        return self.block_hash.as_ref().unwrap();
    }

    pub fn fetch_storage_dump(&mut self, address: EVMAddress) -> Option<Arc<HashMap<EVMU256, EVMU256>>> {
        if let Some(storage) = self.storage_dump_cache.get(&address) {
            storage.clone()
        } else {
            let storage = self.fetch_storage_dump_uncached(address);
            self.storage_dump_cache.insert(address, storage.clone());
            storage
        }
    }

    pub fn fetch_storage_dump_uncached(&mut self, address: EVMAddress) -> Option<Arc<HashMap<EVMU256, EVMU256>>> {
        let resp = {
            let blk_hash = self.fetch_blk_hash();
            let mut params = String::from("[");
            params.push_str(&format!("\"{}\",", blk_hash));
            params.push_str("0,");
            params.push_str(&format!("\"0x{:x}\",", address));
            params.push_str("\"\",");
            params.push_str("1000000000000000");
            params.push(']');
            self._request("debug_storageRangeAt".to_string(), params)
        };

        match resp {
            Some(resp) => {
                let mut map = HashMap::new();
                let kvs = resp["storage"].as_object().expect("failed to convert resp to array");
                if kvs.is_empty() {
                    return None;
                }
                for (_, v) in kvs.iter() {
                    let key = v["key"].as_str().expect("fail to find key");
                    let value = v["value"].as_str().expect("fail to find value");

                    map.insert(
                        EVMU256::from_str_radix(key.trim_start_matches("0x"), 16).unwrap(),
                        EVMU256::from_str_radix(value.trim_start_matches("0x"), 16).unwrap(),
                    );
                }
                Some(Arc::new(map))
            }
            None => None,
        }
    }

    pub fn fetch_abi_uncached(&self, address: EVMAddress) -> Option<String> {
        if self.chain_name == "vana" {
            return self.fetch_vana_abi_uncached(address);
        }

        #[cfg(feature = "no_etherscan")]
        {
            return None;
        }
        let endpoint = format!(
            "{}?module=contract&action=getabi&address={:?}&format=json&apikey={}",
            self.etherscan_base,
            address,
            if !self.etherscan_api_key.is_empty() {
                self.etherscan_api_key[rand::random::<usize>() % self.etherscan_api_key.len()].clone()
            } else {
                "".to_string()
            }
        );
        info!("fetching abi from {}", endpoint);
        match self.get(endpoint.clone()) {
            Some(resp) => {
                let json = serde_json::from_str::<Value>(&resp);
                match json {
                    Ok(json) => {
                        let result_parsed = json["result"].as_str();
                        match result_parsed {
                            Some(result) => {
                                if result == "Contract source code not verified" {
                                    None
                                } else {
                                    Some(result.to_string())
                                }
                            }
                            _ => None,
                        }
                    }
                    Err(_) => None,
                }
            }
            None => {
                error!("failed to fetch abi from {}", endpoint);
                None
            }
        }
    }

    fn fetch_vana_abi_uncached(&self, address: EVMAddress) -> Option<String> {
        let endpoint = format!("{}/smart-contracts/{:?}", self.etherscan_base, address);

        // info!(">> {}", endpoint);
        match self.get(endpoint.clone()) {
            Some(resp) => match serde_json::from_str::<Value>(&resp) {
                Ok(json) => {
                    // info!("<< {}", json);
                    json.get("abi").map(|abi| abi.to_string())
                }
                Err(_) => {
                    error!("Failed to parse JSON response from Vana API");
                    None
                }
            },
            None => {
                error!("Failed to fetch ABI from Vana API: {}", endpoint);
                None
            }
        }
    }

    pub fn fetch_abi(&mut self, address: EVMAddress) -> Option<String> {
        if self.abi_cache.contains_key(&address) {
            return self.abi_cache.get(&address).unwrap().clone();
        }
        let abi = self.fetch_abi_uncached(address);
        self.abi_cache.insert(address, abi.clone());
        abi
    }

    pub fn _request(&self, method: String, params: String) -> Option<Value> {
        let data = format!(
            "{{\"jsonrpc\":\"2.0\", \"method\": \"{}\", \"params\": {}, \"id\": {}}}",
            method, params, self.chain_id
        );

        // Handling HTTP request
        if self.endpoint_url.starts_with("http://") || self.endpoint_url.starts_with("https://") {
            let client = reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("Failed to create HTTP client");

            return client
                .post(&self.endpoint_url)
                .header("Content-Type", "application/json")
                .body(data)
                .send()
                .ok()
                .and_then(|resp| resp.text().ok())
                .and_then(|resp| serde_json::from_str(&resp).ok())
                .and_then(|json: Value| json.get("result").cloned());
        }
        // Handling IPC request
        else if self.endpoint_url.starts_with("/") ||
            self.endpoint_url.starts_with("./") ||
            self.endpoint_url.starts_with("../")
        {
            match UnixStream::connect(&self.endpoint_url) {
                Ok(mut socket) => {
                    socket
                        .set_read_timeout(Some(Duration::from_secs(10)))
                        .expect("Failed to set read timeout");
                    socket
                        .set_write_timeout(Some(Duration::from_secs(5)))
                        .expect("Failed to set write timeout");

                    if let Err(e) = socket.write_all(data.as_bytes()) {
                        error!("Failed to write to IPC stream: {}", e);
                        return None;
                    }

                    let mut response = String::new();
                    let mut buffer = [0; 4096];
                    let timeout = Duration::from_secs(10);
                    let start_time = Instant::now();

                    while start_time.elapsed() < timeout {
                        match socket.read(&mut buffer) {
                            Ok(0) => {
                                error!("No data read from IPC stream; the stream might have been closed.");
                                return None;
                            }
                            Ok(n) => {
                                response.push_str(&String::from_utf8_lossy(&buffer[..n]));
                                if response.contains("\n") {
                                    break;
                                }
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                            Err(e) => {
                                error!("Failed to read from IPC stream: {}", e);
                                return None;
                            }
                        }
                    }

                    if start_time.elapsed() >= timeout {
                        error!("Timeout reached while reading from the IPC stream.");
                        return None;
                    }

                    serde_json::from_str(&response)
                        .ok()
                        .and_then(|json: Value| json.get("result").cloned())
                }
                Err(e) => {
                    error!("IPC connection failed: {}", e);
                    return None;
                }
            }
        } else {
            error!("Unsupported URL scheme: {}", self.endpoint_url);
            None
        }
    }

    fn _request_with_id(&self, method: String, params: String, id: u8) -> Option<Value> {
        let data = format!(
            "{{\"jsonrpc\":\"2.0\", \"method\": \"{}\", \"params\": {}, \"id\": {}}}",
            method, params, id
        );

        // Handling HTTP request
        if self.endpoint_url.starts_with("http://") || self.endpoint_url.starts_with("https://") {
            let client = reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("Failed to create HTTP client");

            return client
                .post(&self.endpoint_url)
                .header("Content-Type", "application/json")
                .body(data)
                .send()
                .ok()
                .and_then(|resp| resp.text().ok())
                .and_then(|resp| serde_json::from_str(&resp).ok())
                .and_then(|json: Value| json.get("result").cloned());
        }
        // Handling IPC request
        else if self.endpoint_url.starts_with("/") ||
            self.endpoint_url.starts_with("./") ||
            self.endpoint_url.starts_with("../")
        {
            match UnixStream::connect(&self.endpoint_url) {
                Ok(mut socket) => {
                    socket
                        .set_read_timeout(Some(Duration::from_secs(10)))
                        .expect("Failed to set read timeout");
                    socket
                        .set_write_timeout(Some(Duration::from_secs(5)))
                        .expect("Failed to set write timeout");

                    if let Err(e) = socket.write_all(data.as_bytes()) {
                        error!("Failed to write to IPC stream: {}", e);
                        return None;
                    }

                    let mut response = String::new();
                    let mut buffer = [0; 4096];
                    let timeout = Duration::from_secs(10);
                    let start_time = Instant::now();

                    while start_time.elapsed() < timeout {
                        match socket.read(&mut buffer) {
                            Ok(0) => {
                                error!("No data read from IPC stream; the stream might have been closed.");
                                return None;
                            }
                            Ok(n) => {
                                response.push_str(&String::from_utf8_lossy(&buffer[..n]));
                                if response.contains("\n") {
                                    break;
                                }
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                            Err(e) => {
                                error!("Failed to read from IPC stream: {}", e);
                                return None;
                            }
                        }
                    }

                    if start_time.elapsed() >= timeout {
                        error!("Timeout reached while reading from the IPC stream.");
                        return None;
                    }

                    serde_json::from_str(&response)
                        .ok()
                        .and_then(|json: Value| json.get("result").cloned())
                }
                Err(e) => {
                    error!("IPC connection failed: {}", e);
                    return None;
                }
            }
        } else {
            error!("Unsupported URL scheme: {}", self.endpoint_url);
            None
        }
    }

    pub fn get_balance(&mut self, address: EVMAddress) -> EVMU256 {
        if self.balance_cache.contains_key(&address) {
            return self.balance_cache[&address];
        }

        let resp_string = {
            let mut params = String::from("[");
            params.push_str(&format!("\"0x{:x}\",", address));
            params.push_str(&format!("\"{}\"", self.block_number));
            params.push(']');
            let resp = self._request("eth_getBalance".to_string(), params);
            match resp {
                Some(resp) => {
                    let balance = resp.as_str().unwrap();
                    balance.to_string()
                }
                None => "".to_string(),
            }
        };
        let balance = EVMU256::from_str(&resp_string).unwrap();
        info!("balance of {address:?} at {} is {balance}", self.block_number);
        self.balance_cache.insert(address, balance);
        balance
    }

    pub fn eth_call(&mut self, address: EVMAddress, calldata: Bytes) -> Bytes {
        let call = format!(
            "\"from\": null,\"to\":\"{:?}\",\"data\":\"0x{}\"",
            address,
            hex::encode(calldata.to_vec())
        );
        let wrapped_call = format!("[{{{}}},\"{}\"]", call, self.block_number);
        // println!("wrapped_call: {}", wrapped_call);
        let resp_string = {
            let resp = self._request("eth_call".to_string(), wrapped_call);
            match resp {
                Some(resp) => {
                    let res = resp.as_str().unwrap();
                    res.to_string()
                }
                None => "".to_string(),
            }
        };
        let call_result = Bytes::from(hex::decode(resp_string.trim_start_matches("0x")).unwrap());
        call_result
    }

    pub fn get_token_balance(&mut self, token: EVMAddress, address: EVMAddress) -> EVMU256 {
        let data = format!("70a08231000000000000000000000000{:x}", address);
        let balance = self.eth_call(token, Bytes::from(hex::decode(data).unwrap()));
        EVMU256::from_be_slice(&balance)
    }

    pub fn get_v3_fee(&mut self, address: EVMAddress) -> u32 {
        let data = "ddca3f43".to_string();
        let fee = self.eth_call(address, Bytes::from(hex::decode(data).unwrap()));
        u32::from_be_bytes([fee[28], fee[29], fee[30], fee[31]])
    }

    pub fn fetch_blk_timestamp(&mut self) -> EVMU256 {
        if self.timestamp.is_none() {
            self.timestamp = {
                let mut params = String::from("[");
                params.push_str(&format!("\"{}\",false", self.block_number));
                params.push(']');
                let res = self._request("eth_getBlockByNumber".to_string(), params);
                match res {
                    Some(res) => {
                        let blk_timestamp = res["timestamp"]
                            .as_str()
                            .expect("fail to find block timestamp")
                            .to_string();
                        Some(blk_timestamp)
                    }
                    None => panic!("fail to get block timestamp"),
                }
            }
        }
        let timestamp = EVMU256::from_str(self.timestamp.as_ref().unwrap()).unwrap();
        timestamp
    }

    pub fn fetch_blk_coinbase(&mut self) -> EVMAddress {
        if self.coinbase.is_none() {
            self.coinbase = {
                let mut params = String::from("[");
                params.push_str(&format!("\"{}\",false", self.block_number));
                params.push(']');
                let res = self._request("eth_getBlockByNumber".to_string(), params);
                match res {
                    Some(res) => {
                        let blk_coinbase = res["miner"].as_str().expect("fail to find block coinbase").to_string();
                        Some(blk_coinbase)
                    }
                    None => panic!("fail to get block coinbase"),
                }
            }
        }
        let coinbase = EVMAddress::from_str(self.coinbase.as_ref().unwrap()).unwrap();
        coinbase
    }

    pub fn fetch_blk_gaslimit(&mut self) -> EVMU256 {
        if self.gaslimit.is_none() {
            self.gaslimit = {
                let mut params = String::from("[");
                params.push_str(&format!("\"{}\",false", self.block_number));
                params.push(']');
                let res = self._request("eth_getBlockByNumber".to_string(), params);
                match res {
                    Some(res) => {
                        let blk_gaslimit = res["gasLimit"]
                            .as_str()
                            .expect("fail to find block coinbase")
                            .to_string();
                        Some(blk_gaslimit)
                    }
                    None => panic!("fail to get block coinbase"),
                }
            }
        }
        let gaslimit = EVMU256::from_str(self.gaslimit.as_ref().unwrap()).unwrap();
        gaslimit
    }

    pub fn get_contract_code(&mut self, address: EVMAddress, force_cache: bool) -> String {
        if self.code_cache.contains_key(&address) {
            return self.code_cache[&address].clone();
        }
        if force_cache {
            return "".to_string();
        }

        info!("fetching code from {}", hex::encode(address));

        let resp_string = {
            let mut params = String::from("[");
            params.push_str(&format!("\"0x{:x}\",", address));
            params.push_str(&format!("\"{}\"", self.block_number));
            params.push(']');
            let resp = self._request("eth_getCode".to_string(), params);
            match resp {
                Some(resp) => {
                    let code = resp.as_str().unwrap();
                    code.to_string()
                }
                None => "".to_string(),
            }
        }
        .trim_start_matches("0x")
        .to_string();
        self.code_cache.insert(address, resp_string.clone());
        resp_string
    }

    pub fn get_contract_code_analyzed(&mut self, address: EVMAddress, force_cache: bool) -> Bytecode {
        if self.code_cache_analyzed.contains_key(&address) {
            return self.code_cache_analyzed[&address].clone();
        }

        let code = self.get_contract_code(address, force_cache);
        let contract_code = to_analysed(Bytecode::new_raw(Bytes::from(
            hex::decode(code).expect("fail to decode contract code"),
        )));
        let contract_code = to_analysed(contract_code);
        self.code_cache_analyzed.insert(address, contract_code.clone());
        contract_code
    }

    pub fn get_contract_slot(&mut self, address: EVMAddress, slot: EVMU256, force_cache: bool) -> EVMU256 {
        if self.slot_cache.contains_key(&(address, slot)) {
            return self.slot_cache[&(address, slot)];
        }
        if force_cache {
            return EVMU256::ZERO;
        }

        let resp_string = {
            let mut params = String::from("[");
            params.push_str(&format!("\"0x{:x}\",", address));
            params.push_str(&format!("\"0x{:x}\",", slot));
            params.push_str(&format!("\"{}\"", self.block_number));
            params.push(']');
            let resp = self._request("eth_getStorageAt".to_string(), params);
            match resp {
                Some(resp) => {
                    let slot_data = resp.as_str().unwrap();
                    slot_data.to_string()
                }
                None => "".to_string(),
            }
        };

        let slot_suffix = resp_string.trim_start_matches("0x");

        if slot_suffix.is_empty() {
            self.slot_cache.insert((address, slot), EVMU256::ZERO);
            return EVMU256::ZERO;
        }
        let slot_value = EVMU256::try_from_be_slice(&hex::decode(slot_suffix).unwrap()).unwrap();
        self.slot_cache.insert((address, slot), slot_value);
        slot_value
    }
}

impl OnChainConfig {
    pub fn get_pair(&mut self, token: &str, network: &str, is_pegged: bool, weth: String) -> Vec<PairData> {
        let token: String = token.to_lowercase();
        if self.pair_cache.contains_key(&EVMAddress::from_str(&token).unwrap()) {
            return self.pair_cache[&EVMAddress::from_str(&token).unwrap()].clone();
        }
        info!("fetching pairs for {token}");
        let url = if is_pegged {
            format!("https://pairs-all.infra.fuzz.land/single_pair/{network}/{token}/{weth}")
        } else {
            format!("https://pairs-all.infra.fuzz.land/pairs/{network}/{token}")
        };
        // info!("{url}");
        let resp: Value = reqwest::blocking::get(url).unwrap().json().unwrap();
        let mut pairs: Vec<PairData> = Vec::new();
        if let Some(resp_pairs) = resp.as_array() {
            for item in resp_pairs {
                let pair = item["pair"].as_str().unwrap().to_string();
                let code = self.get_contract_code(EVMAddress::from_str(&pair).unwrap(), false);
                if code.is_empty() {
                    continue;
                }
                let token0 = item["token0"].as_str().unwrap().to_string();
                let token1 = item["token1"].as_str().unwrap().to_string();

                let token0_decimals = item["token0_decimals"].as_i64().unwrap();
                let token1_decimals = item["token1_decimals"].as_i64().unwrap();
                let data = PairData {
                    src: if is_pegged { "pegged" } else { "lp" }.to_string(),
                    in_: if token == token0 { 0 } else { 1 },
                    pair,
                    next: if token == token0 {
                        token1.clone()
                    } else {
                        token0.clone()
                    },
                    in_token: token.clone(),
                    interface: item["interface"].as_str().unwrap().to_string(),
                    src_exact: item["src_exact"].as_str().unwrap().to_string(),
                    initial_reserves_0: EVMU256::ZERO,
                    initial_reserves_1: EVMU256::ZERO,
                    decimals_0: if token0_decimals >= 0 {
                        token0_decimals as u32
                    } else {
                        0
                    },
                    decimals_1: if token1_decimals >= 0 {
                        token1_decimals as u32
                    } else {
                        0
                    },
                    token0,
                    token1,
                };
                pairs.push(data);
            }
        }
        self.pair_cache
            .insert(EVMAddress::from_str(&token).unwrap(), pairs.clone());
        pairs
    }

    pub fn fetch_reserve(&self, pair: &str) -> Option<(String, String)> {
        let result = {
            let params = json!([{
            "to": pair,
            "data": "0x0902f1ac",
            "id": 1
        }, self.block_number]);
            debug!("fetching reserve for {pair} {}", self.block_number);
            let resp = self._request_with_id("eth_call".to_string(), params.to_string(), 1);
            match resp {
                Some(resp) => resp.to_string(),
                None => "".to_string(),
            }
        };

        if result.len() != 196 {
            let rpc = &self.endpoint_url;
            let pair_code = self.clone().get_contract_code(B160::from_str(pair).unwrap(), true);
            info!("rpc: {rpc}, result: {result}, pair: {pair}, pair code: {pair_code}");
            info!("Unexpected RPC error, consider setting env <ETH_RPC_URL> ");
            return None;
        }

        let reserve1 = &result[3..67];
        let reserve2 = &result[67..131];

        Some((reserve1.into(), reserve2.into()))
    }
}

fn get_header() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("authority", "etherscan.io".parse().unwrap());
    headers.insert("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9".parse().unwrap());
    headers.insert("accept-language", "zh-CN,zh;q=0.9,en;q=0.8".parse().unwrap());
    headers.insert("cache-control", "max-age=0".parse().unwrap());
    headers.insert(
        "sec-ch-ua",
        "\"Not?A_Brand\";v=\"8\", \"Chromium\";v=\"108\", \"Google Chrome\";v=\"108\""
            .parse()
            .unwrap(),
    );
    headers.insert("sec-ch-ua-mobile", "?0".parse().unwrap());
    headers.insert("sec-ch-ua-platform", "\"macOS\"".parse().unwrap());
    headers.insert("sec-fetch-dest", "document".parse().unwrap());
    headers.insert("sec-fetch-mode", "navigate".parse().unwrap());
    headers.insert("sec-fetch-site", "none".parse().unwrap());
    headers.insert("sec-fetch-user", "?1".parse().unwrap());
    headers.insert("upgrade-insecure-requests", "1".parse().unwrap());
    headers.insert("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36".parse().unwrap());
    headers.insert("Content-Type", "application/json".parse().unwrap());
    headers
}

#[cfg(test)]
mod tests {
    use tracing::debug;

    use super::*;
    use crate::evm::{
        onchain::endpoints::Chain::{BSC, ETH},
        types::EVMAddress,
    };

    #[test]
    fn test_onchain_config() {
        let config = OnChainConfig::new(BSC, 0);
        let v = config._request(
            "eth_getCode".to_string(),
            "[\"0x0000000000000000000000000000000000000000\", \"latest\"]".to_string(),
        );
        debug!("{:?}", v)
    }

    #[test]
    fn test_get_contract_slot() {
        let mut config = OnChainConfig::new(BSC, 0);
        let v = config.get_contract_slot(
            EVMAddress::from_str("0xb486857fac4254a7ffb3b1955ee0c0a2b2ca75ab").unwrap(),
            EVMU256::from(3),
            false,
        );
        debug!("{:?}", v)
    }

    #[test]
    fn test_fetch_abi() {
        let mut config = OnChainConfig::new(BSC, 0);
        let v = config.fetch_abi(EVMAddress::from_str("0xa0a2ee912caf7921eaabc866c6ef6fec8f7e90a4").unwrap());
        debug!("{:?}", v)
    }

    #[test]
    fn test_get_balance() {
        let mut config = OnChainConfig::new(ETH, 18168677);
        let v = config.get_balance(EVMAddress::from_str("0x1f9090aaE28b8a3dCeaDf281B0F12828e676c326").unwrap());
        debug!("{:?}", v);
        assert!(v == EVMU256::from(439351222497229612i64));
    }

    #[test]
    fn test_get_pair_pegged() {
        let mut config = OnChainConfig::new(BSC, 22055611);
        let v = config.get_pair(
            "0x0e09fabb73bd3ade0a17ecc321fd13a19e81ce82",
            "bsc",
            true,
            "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c".to_string(),
        );
        assert!(!v.is_empty() && v.len() < 10);
    }

    #[test]
    fn test_get_token_balance() {
        let mut config = OnChainConfig::new(BSC, 37381166);
        let v = config.get_token_balance(
            EVMAddress::from_str("0xfb5B838b6cfEEdC2873aB27866079AC55363D37E").unwrap(),
            EVMAddress::from_str("0xf977814e90da44bfa03b6295a0616a897441acec").unwrap(),
        );
        println!("{:?}", v);
    }

    #[test]
    fn get_v3_fee() {
        let mut config = OnChainConfig::new(BSC, 37381166);
        let v = config.get_v3_fee(EVMAddress::from_str("0x4f31fa980a675570939b737ebdde0471a4be40eb").unwrap());
        println!("{:?}", v);
    }

    // #[test]
    // fn test_fetch_token_price() {
    //     let mut config = OnChainConfig::new(BSC, 0);
    //     config.add_moralis_api_key(
    //         "ocJtTEZWOJZjYOMAQjRmWcHpvUdieMLJDAtUjycFNTdSxgFGofNJhdiRX0Kk1h1O".to_string(),
    //     );
    //     let v = config.fetch_token_price(
    //         EVMAddress::from_str("0xa0a2ee912caf7921eaabc866c6ef6fec8f7e90a4"
    // ).unwrap(),     );
    //     debug!("{:?}", v)
    // }
    //
    // #[test]
    // fn test_fetch_storage_all() {
    //     let mut config = OnChainConfig::new(BSC, 0);
    //     let v = config.fetch_storage_all(
    //         EVMAddress::from_str("0x2aB472b185787b665f334F12618254CaCA668e49"
    // ).unwrap(),     );
    //     debug!("{:?}", v)
    // }

    // #[test]
    // fn test_fetch_storage_dump() {
    //     let mut config = OnChainConfig::new(ETH, 0);
    //     let v = config
    //         .fetch_storage_dump(
    //
    // EVMAddress::from_str("0x3ea826a2724f3df727b64db552f3103192158c58").
    // unwrap(),         )
    //         .unwrap();

    //     let v0 = v.get(&EVMU256::from(0)).unwrap().clone();

    //     let slot_v = config.get_contract_slot(
    //         EVMAddress::from_str("0x3ea826a2724f3df727b64db552f3103192158c58"
    // ).unwrap(),         EVMU256::from(0),
    //         false,
    //     );

    //     assert_eq!(slot_v, v0);
    // }
}
