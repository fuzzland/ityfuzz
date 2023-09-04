use crate::cache::{Cache, FileSystemCache};
use crate::evm::uniswap::{
    get_uniswap_info, PairContext, PathContext, TokenContext, UniswapProvider,
};
use bytes::Bytes;
use reqwest::header::HeaderMap;
use retry::OperationResult;
use retry::{delay::Fixed, retry_with_index};
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};

use crate::evm::types::{EVMAddress, EVMU256};
use revm_interpreter::analysis::to_analysed;
use revm_primitives::bitvec::macros::internal::funty::Integral;
use revm_primitives::{Bytecode, LatestSpec};
use serde::Deserialize;
use serde_json::{json, Value};
use std::cell::RefCell;
use std::fmt::Debug;
use std::panic;
use std::rc::Rc;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

const MAX_HOPS: u32 = 2; // Assuming the value of MAX_HOPS

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
    ZKEVM_TESTNET,
    LOCAL,
}

pub trait PriceOracle: Debug {
    // ret0: price = int(original_price x 10^5)
    // ret1: decimals of the token
    fn fetch_token_price(&mut self, token_address: EVMAddress) -> Option<(u32, u32)>;
}

impl Chain {
    pub fn from_str(s: &String) -> Option<Self> {
        match s.as_str() {
            "ETH" | "eth" => Some(Self::ETH),
            "GOERLI" | "goerli" => Some(Self::GOERLI),
            "SEPOLIA" | "sepolia" => Some(Self::SEPOLIA),
            "BSC" | "bsc" => Some(Self::BSC),
            "CHAPEL" | "chapel" => Some(Self::CHAPEL),
            "POLYGON" | "polygon" => Some(Self::POLYGON),
            "MUMBAI" | "mumbai" => Some(Self::MUMBAI),
            "FANTOM" | "fantom" => Some(Self::FANTOM),
            "AVALANCHE" | "avalanche" => Some(Self::AVALANCHE),
            "OPTIMISM" | "optimism" => Some(Self::OPTIMISM),
            "ARBITRUM" | "arbitrum" => Some(Self::ARBITRUM),
            "GNOSIS" | "gnosis" => Some(Self::GNOSIS),
            "BASE" | "base" => Some(Self::BASE),
            "CELO" | "celo" => Some(Self::CELO),
            "ZKEVM" | "zkevm" => Some(Self::ZKEVM),
            "ZKEVM_TESTNET" | "zkevm_testnet" => Some(Self::ZKEVM_TESTNET),
            "LOCAL" | "local" => Some(Self::LOCAL),
            _ => None,
        }
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
            Chain::ZKEVM_TESTNET => 1442,
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
            Chain::ZKEVM_TESTNET => "zkevm_testnet",
            Chain::LOCAL => "local",
        }
        .to_string()
    }

    pub fn get_chain_rpc(&self) -> String {
        match self {
            Chain::ETH => "https://eth.llamarpc.com",
            Chain::GOERLI => "https://rpc.ankr.com/eth_goerli",
            Chain::SEPOLIA => "https://rpc.ankr.com/eth_sepolia",
            Chain::BSC => "https://rpc.ankr.com/bsc",
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
            Chain::ZKEVM_TESTNET => "https://rpc.ankr.com/polygon_zkevm_testnet",
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
            Chain::ZKEVM_TESTNET => "https://api-testnet-zkevm.polygonscan.com/api",
            Chain::LOCAL => "http://localhost:8080/abi/",
        }
        .to_string()
    }
}

#[derive(Clone, Debug, Default)]
pub struct PairData {
    src: String,
    in_: i32,
    pair: String,
    next: String,
    decimals0: i32,
    decimals1: i32,
    src_exact: String,
    rate: u32,
    token: String,
    initial_reserves_0: String,
    initial_reserves_1: String,
}

pub struct Info {
    routes: Vec<Vec<PairData>>,
    basic_info: BasicInfo,
}

pub struct BasicInfo {
    weth: String,
    is_weth: bool,
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

#[derive(Clone, Debug)]
pub struct OnChainConfig {
    pub endpoint_url: String,
    // pub cache_len: usize,
    //
    // code_cache: HashMap<EVMAddress, Bytecode>,
    // slot_cache: HashMap<(EVMAddress, EVMU256), EVMU256>,
    pub client: reqwest::blocking::Client,
    pub chain_id: u32,
    pub block_number: String,
    pub block_hash: Option<String>,

    pub etherscan_api_key: Vec<String>,
    pub etherscan_base: String,

    pub chain_name: String,

    slot_cache: HashMap<(EVMAddress, EVMU256), EVMU256>,
    code_cache: HashMap<EVMAddress, Bytecode>,
    price_cache: HashMap<EVMAddress, Option<(u32, u32)>>,
    abi_cache: HashMap<EVMAddress, Option<String>>,
    storage_all_cache: HashMap<EVMAddress, Option<Arc<HashMap<String, EVMU256>>>>,
    storage_dump_cache: HashMap<EVMAddress, Option<Arc<HashMap<EVMU256, EVMU256>>>>,
    uniswap_path_cache: HashMap<EVMAddress, TokenContext>,
    rpc_cache: FileSystemCache,
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
        Self {
            endpoint_url,
            client: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(20))
                .build()
                .expect("build client failed"),
            chain_id,
            block_number: if block_number == 0 {
                "latest".to_string()
            } else {
                format!("0x{:x}", block_number)
            },
            block_hash: None,
            etherscan_api_key: vec![],
            etherscan_base,
            chain_name: chain_name,
            slot_cache: Default::default(),
            code_cache: Default::default(),
            price_cache: Default::default(),
            abi_cache: Default::default(),

            storage_all_cache: Default::default(),
            storage_dump_cache: Default::default(),
            uniswap_path_cache: Default::default(),
            rpc_cache: FileSystemCache::new("./cache"),
        }
    }

    fn get(&self, url: String) -> Option<String> {
        let mut hasher = DefaultHasher::new();
        let key = format!("post_{}", url.as_str());
        key.hash(&mut hasher);
        let hash = hasher.finish().to_string();
        if let Ok(t) = self.rpc_cache.load(hash.as_str()) {
            return Some(t);
        }
        match retry_with_index(Fixed::from_millis(1000), |current_try| {
            if current_try > 5 {
                return OperationResult::Err("did not succeed within 3 tries".to_string());
            }
            match self
                .client
                .get(url.to_string())
                .headers(get_header())
                .send()
            {
                Ok(resp) => {
                    let text = resp.text();
                    match text {
                        Ok(t) => {
                            if t.contains("Max rate limit reached") {
                                println!("Etherscan max rate limit reached, retrying...");
                                return OperationResult::Retry("Rate limit reached".to_string());
                            } else {
                                return OperationResult::Ok(t);
                            }
                        }
                        Err(e) => {
                            println!("{:?}", e);
                            return OperationResult::Retry("failed to parse response".to_string());
                        }
                    }
                }
                Err(e) => {
                    println!("Error: {}", e);
                    return OperationResult::Retry("failed to send request".to_string());
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
                println!("Error: {}", e);
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
                        Ok(t) => {
                            return OperationResult::Ok(t);
                        }
                        Err(e) => {
                            println!("{:?}", e);
                            return OperationResult::Retry("failed to parse response".to_string());
                        }
                    }
                }
                Err(e) => {
                    println!("Error: {}", e);
                    return OperationResult::Retry("failed to send request".to_string());
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
                println!("Error: {}", e);
                None
            }
        }
    }

    pub fn add_etherscan_api_key(&mut self, key: String) {
        self.etherscan_api_key.push(key);
    }

    pub fn fetch_storage_all(
        &mut self,
        address: EVMAddress,
    ) -> Option<Arc<HashMap<String, EVMU256>>> {
        if let Some(storage) = self.storage_all_cache.get(&address) {
            return storage.clone();
        } else {
            let storage = self.fetch_storage_all_uncached(address);
            self.storage_all_cache.insert(address, storage.clone());
            storage
        }
    }

    pub fn fetch_storage_all_uncached(
        &self,
        address: EVMAddress,
    ) -> Option<Arc<HashMap<String, EVMU256>>> {
        assert_eq!(
            self.block_number, "latest",
            "fetch_full_storage only works with latest block"
        );
        let resp = {
            let mut params = String::from("[");
            params.push_str(&format!("\"0x{:x}\",", address));
            params.push_str(&format!("\"{}\"", self.block_number));
            params.push_str("]");
            self._request("eth_getStorageAll".to_string(), params)
        };

        match resp {
            Some(resp) => {
                let mut map = HashMap::new();
                for (k, v) in resp.as_object()
                    .expect("failed to convert resp to array, are you using a node that supports eth_getStorageAll?")
                    .iter()
                {
                    map.insert(
                        k.trim_start_matches("0x").to_string(),
                        EVMU256::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap(),
                    );
                }
                Some(Arc::new(map))
            }
            None => None,
        }
    }

    pub fn fetch_blk_hash(&mut self) -> &String {
        if self.block_hash == None {
            self.block_hash = {
                let mut params = String::from("[");
                params.push_str(&format!("\"{}\",false", self.block_number));
                params.push_str("]");
                let res = self._request("eth_getBlockByNumber".to_string(), params);
                match res {
                    Some(res) => {
                        let blk_hash = res["hash"]
                            .as_str()
                            .expect("fail to find block hash")
                            .to_string();
                        Some(blk_hash)
                    }
                    None => panic!("fail to get block hash"),
                }
            }
        }
        return self.block_hash.as_ref().unwrap();
    }

    pub fn fetch_storage_dump(
        &mut self,
        address: EVMAddress,
    ) -> Option<Arc<HashMap<EVMU256, EVMU256>>> {
        if let Some(storage) = self.storage_dump_cache.get(&address) {
            return storage.clone();
        } else {
            let storage = self.fetch_storage_dump_uncached(address);
            self.storage_dump_cache.insert(address, storage.clone());
            storage
        }
    }

    pub fn fetch_storage_dump_uncached(
        &mut self,
        address: EVMAddress,
    ) -> Option<Arc<HashMap<EVMU256, EVMU256>>> {
        let resp = {
            let blk_hash = self.fetch_blk_hash();
            let mut params = String::from("[");
            params.push_str(&format!("\"{}\",", blk_hash));
            params.push_str("0,");
            params.push_str(&format!("\"0x{:x}\",", address));
            params.push_str("\"\",");
            params.push_str(&format!("1000000000000000"));
            params.push_str("]");
            self._request("debug_storageRangeAt".to_string(), params)
        };

        match resp {
            Some(resp) => {
                let mut map = HashMap::new();
                let kvs = resp["storage"]
                    .as_object()
                    .expect("failed to convert resp to array");
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
        let endpoint = format!(
            "{}?module=contract&action=getabi&address={:?}&format=json&apikey={}",
            self.etherscan_base,
            address,
            if self.etherscan_api_key.len() > 0 {
                self.etherscan_api_key[rand::random::<usize>() % self.etherscan_api_key.len()]
                    .clone()
            } else {
                "".to_string()
            }
        );
        println!("fetching abi from {}", endpoint);
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
                println!("failed to fetch abi from {}", endpoint);
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

    fn _request(&self, method: String, params: String) -> Option<Value> {
        let data = format!(
            "{{\"jsonrpc\":\"2.0\", \"method\": \"{}\", \"params\": {}, \"id\": {}}}",
            method, params, self.chain_id
        );

        match self.post(self.endpoint_url.clone(), data) {
            Some(resp) => {
                let json: Result<Value, _> = serde_json::from_str(&resp);

                match json {
                    Ok(json) => {
                        return json.get("result").cloned();
                    }
                    Err(e) => {
                        println!("{:?}", e);
                        None
                    }
                }
            }

            None => {
                println!("failed to fetch from {}", self.endpoint_url);
                None
            }
        }
    }

    fn _request_with_id(&self, method: String, params: String, id: u8) -> Option<Value> {
        let data = format!(
            "{{\"jsonrpc\":\"2.0\", \"method\": \"{}\", \"params\": {}, \"id\": {}}}",
            method, params, id
        );

        match self.post(self.endpoint_url.clone(), data) {
            Some(resp) => {
                let json: Result<Value, _> = serde_json::from_str(&resp);

                match json {
                    Ok(json) => {
                        return json.get("result").cloned();
                    }
                    Err(e) => {
                        println!("{:?}", e);
                        None
                    }
                }
            }

            None => {
                println!("failed to fetch from {}", self.endpoint_url);
                None
            }
        }
    }

    pub fn get_contract_code(&mut self, address: EVMAddress, force_cache: bool) -> Bytecode {
        if self.code_cache.contains_key(&address) {
            return self.code_cache[&address].clone();
        }
        if force_cache {
            return Bytecode::default();
        }

        println!("fetching code from {}", hex::encode(address));

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
        };
        let code = resp_string.trim_start_matches("0x");
        if code.is_empty() {
            self.code_cache.insert(address, Bytecode::new());
            return Bytecode::new();
        }
        let code = hex::decode(code).unwrap();
        let bytes = to_analysed(Bytecode::new_raw(Bytes::from(code)));
        self.code_cache.insert(address, bytes.clone());
        bytes
    }

    pub fn get_contract_slot(
        &mut self,
        address: EVMAddress,
        slot: EVMU256,
        force_cache: bool,
    ) -> EVMU256 {
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
        return slot_value;
    }

    pub fn fetch_uniswap_path(&self, token_address: EVMAddress) -> TokenContext {
        let token = format!("{:?}", token_address);
        let info: Info = self.find_path_subgraph(&self.chain_name, &token, &self.block_number);

        let basic_info = info.basic_info;
        let weth = EVMAddress::from_str(&basic_info.weth).expect("failed to parse weth");
        let is_weth = basic_info.is_weth;

        let routes = info.routes;

        let paths_parsed = routes
            .iter()
            .map(|pairs| {
                let mut path_parsed: PathContext = Default::default();
                pairs.iter().for_each(|pair| {
                    match pair.src.as_str() {
                        "v2" => {
                            // let decimals0 = pair["decimals0"].as_u64().expect("failed to parse decimals0");
                            // let decimals1 = pair["decimals1"].as_u64().expect("failed to parse decimals1");
                            // let next = EVMAddress::from_str(pair["next"].as_str().expect("failed to parse next")).expect("failed to parse next");

                            path_parsed.route.push(Rc::new(RefCell::new(PairContext {
                                pair_address: EVMAddress::from_str(pair.pair.as_str())
                                    .expect("failed to parse pair"),
                                next_hop: EVMAddress::from_str(pair.next.as_str())
                                    .expect("failed to parse pair"),
                                side: pair.in_ as u8,
                                uniswap_info: Arc::new(get_uniswap_info(
                                    &UniswapProvider::from_str(pair.src_exact.as_str()).unwrap(),
                                    &Chain::from_str(&self.chain_name).unwrap(),
                                )),
                                initial_reserves: (
                                    EVMU256::try_from_be_slice(
                                        &hex::decode(&pair.initial_reserves_0).unwrap(),
                                    )
                                    .unwrap(),
                                    EVMU256::try_from_be_slice(
                                        &hex::decode(&pair.initial_reserves_1).unwrap(),
                                    )
                                    .unwrap(),
                                ),
                            })));
                        }
                        "pegged" => {
                            // always live at final
                            path_parsed.final_pegged_ratio = EVMU256::from(pair.rate);
                            path_parsed.final_pegged_pair =
                                Rc::new(RefCell::new(Some(PairContext {
                                    pair_address: EVMAddress::from_str(pair.pair.as_str())
                                        .expect("failed to parse pair"),
                                    next_hop: EVMAddress::from_str(pair.next.as_str())
                                        .expect("failed to parse pair"),
                                    side: pair.in_ as u8,
                                    uniswap_info: Arc::new(get_uniswap_info(
                                        &UniswapProvider::from_str(pair.src_exact.as_str())
                                            .unwrap(),
                                        &Chain::from_str(&self.chain_name).unwrap(),
                                    )),
                                    initial_reserves: (
                                        EVMU256::try_from_be_slice(
                                            &hex::decode(&pair.initial_reserves_0).unwrap(),
                                        )
                                        .unwrap(),
                                        EVMU256::try_from_be_slice(
                                            &hex::decode(&pair.initial_reserves_1).unwrap(),
                                        )
                                        .unwrap(),
                                    ),
                                })));
                        }
                        "pegged_weth" => {
                            path_parsed.final_pegged_ratio = EVMU256::from(pair.rate);
                            path_parsed.final_pegged_pair = Rc::new(RefCell::new(None));
                        }
                        _ => unimplemented!("unknown swap path source"),
                    }
                });
                path_parsed
            })
            .collect();

        TokenContext {
            swaps: paths_parsed,
            is_weth,
            weth_address: weth,
            address: token_address,
        }
    }

    pub fn fetch_uniswap_path_cached(&mut self, token: EVMAddress) -> &TokenContext {
        if self.uniswap_path_cache.contains_key(&token) {
            return self.uniswap_path_cache.get(&token).unwrap();
        }

        let path = self.fetch_uniswap_path(token);
        self.uniswap_path_cache.insert(token, path);
        self.uniswap_path_cache.get(&token).unwrap()
    }
}

impl OnChainConfig {
    fn get_pair(&self, token: &str, network: &str, is_pegged: bool) -> Vec<PairData> {
        // API calls are limited to 300 requests per minute
        let url = format!("https://api.dexscreener.com/latest/dex/tokens/{token}");
        let resp: Value = reqwest::blocking::get(url).unwrap().json().unwrap();
        let mut pairs: Vec<PairData> = Vec::new();
        if let Some(resp_pairs) = resp["pairs"].as_array() {
            for pair in resp_pairs {
                if !pair["chainId"].as_str().unwrap().contains(network) {
                    continue;
                }
                // only v2
                if !pair["labels"]
                    .as_array()
                    .unwrap()
                    .contains(&Value::String("v2".to_string()))
                {
                    continue;
                }
                let base_token = pair["baseToken"].as_object().unwrap()["address"]
                    .as_str()
                    .unwrap()
                    .to_lowercase();
                let quote_token = pair["quoteToken"].as_object().unwrap()["address"]
                    .as_str()
                    .unwrap()
                    .to_lowercase();
                let another_token = if token == base_token {
                    quote_token
                } else {
                    base_token
                };
                let data = PairData {
                    src: if is_pegged { "pegged" } else { "v2" }.to_string(),
                    in_: if token < another_token.as_str() { 0 } else { 1 },
                    pair: pair["pairAddress"].as_str().unwrap().to_lowercase(),
                    next: another_token,
                    decimals0: 18,
                    decimals1: 18,
                    src_exact: "uniswapv2".to_string(),
                    rate: 0,
                    token: token.to_string(),
                    initial_reserves_0: "".to_string(),
                    initial_reserves_1: "".to_string(),
                };
                pairs.push(data);
            }
        }
        pairs
    }

    fn get_weth(&self, network: &str) -> String {
        let pegged_token = self.get_pegged_token(network);

        match network {
            "eth" => return pegged_token.get("WETH").unwrap().to_string(),
            "bsc" => return pegged_token.get("WBNB").unwrap().to_string(),
            "polygon" => return pegged_token.get("WMATIC").unwrap().to_string(),
            "mumbai" => panic!("Not supported"),
            _ => panic!("Unknown network"),
        }
    }

    fn get_pegged_token(&self, network: &str) -> HashMap<String, String> {
        match network {
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
            _ => panic!("[Flashloan] Network is not supported"),
        }
    }

    fn fetch_reserve(&self, pair: &str, block: &str) -> (String, String) {
        let result = {
            let params = json!([{
            "to": pair,
            "data": "0x0902f1ac",
            "id": 1
        }, block]);
            let resp = self._request_with_id("eth_call".to_string(), params.to_string(), 1);
            match resp {
                Some(resp) => resp.to_string(),
                None => "".to_string(),
            }
        };

        let reserve1 = &result[3..67];
        let reserve2 = &result[67..131];

        (reserve1.into(), reserve2.into())
    }

    fn get_all_hops(
        &self,
        token: &str,
        network: &str,
        hop: u32,
        known: &mut HashSet<String>,
    ) -> HashMap<String, Vec<PairData>> {
        known.insert(token.to_string());

        if hop > MAX_HOPS {
            return HashMap::new();
        }

        let mut hops: HashMap<String, Vec<PairData>> = HashMap::new();
        hops.insert(token.to_string(), self.get_pair(token, network, false));

        let pegged_tokens = self.get_pegged_token(network);

        for i in hops.clone().get(token).unwrap() {
            if pegged_tokens.values().any(|v| v == &i.next) || known.contains(&i.next) {
                continue;
            }
            let next_hops = self.get_all_hops(&i.next, network, hop + 1, known);
            hops.extend(next_hops);
        }

        hops
    }

    fn get_pegged_next_hop(&self, token: &str, network: &str, block: &str) -> PairData {
        if token == self.get_weth(network) {
            return PairData {
                src: "pegged_weth".to_string(),
                rate: 1_000_000,
                token: token.to_string(),
                in_: 0,
                next: "".to_string(),
                pair: "".to_string(),
                decimals0: 0,
                decimals1: 0,
                initial_reserves_0: "".to_string(),
                initial_reserves_1: "".to_string(),
                src_exact: "".to_string(),
            };
        }
        let mut peg_info = self.get_pair(token, network, true).get(0).unwrap().clone();

        self.add_reserve_info(&mut peg_info, block);
        let p0 = i128::from_str_radix(&peg_info.initial_reserves_0, 16).unwrap();
        let p1 = i128::from_str_radix(&peg_info.initial_reserves_1, 16).unwrap();

        if peg_info.in_ == 0 {
            peg_info.rate = (p1 as f64 / p0 as f64 * 1_000_000.0).round() as u32;
        } else {
            peg_info.rate = (p0 as f64 / p1 as f64 * 1_000_000.0).round() as u32;
        }

        PairData {
            src: "pegged".to_string(),
            ..peg_info.clone()
        }
    }

    fn add_reserve_info(&self, pair_data: &mut PairData, block: &str) {
        if pair_data.src == "pegged_weth" {
            return;
        }

        let reserves = self.fetch_reserve(&pair_data.pair, block);
        pair_data.initial_reserves_0 = reserves.0;
        pair_data.initial_reserves_1 = reserves.1;
    }

    fn with_info(&self, routes: Vec<Vec<PairData>>, network: &str, token: &str) -> Info {
        Info {
            routes,
            basic_info: BasicInfo {
                weth: self.get_weth(network),
                is_weth: token == self.get_weth(network),
            },
        }
    }

    fn dfs(
        &self,
        token: &str,
        network: &str,
        block: &str,
        path: &mut Vec<PairData>,
        visited: &mut HashSet<String>,
        pegged_tokens: &HashMap<String, String>,
        hops: &HashMap<String, Vec<PairData>>,
        routes: &mut Vec<Vec<PairData>>,
    ) {
        if pegged_tokens.values().any(|v| v == token) {
            let mut new_path = path.clone();
            new_path.push(self.get_pegged_next_hop(token, network, block));
            routes.push(new_path);
            return;
        }
        visited.insert(token.to_string());
        if !hops.contains_key(token) {
            return;
        }
        for hop in hops.get(token).unwrap() {
            if visited.contains(&hop.next) {
                continue;
            }
            path.push(hop.clone());
            self.dfs(
                &hop.next,
                network,
                block,
                path,
                visited,
                pegged_tokens,
                hops,
                routes,
            );
            path.pop();
        }
    }

    fn find_path_subgraph(&self, network: &str, token: &str, block: &str) -> Info {
        let pegged_tokens = self.get_pegged_token(network);

        if pegged_tokens.values().any(|v| v == token) {
            let hop = self.get_pegged_next_hop(token, network, block);
            return self.with_info(vec![vec![hop]], network, token);
        }

        let mut known: HashSet<String> = HashSet::new();
        let hops = self.get_all_hops(token, network, 0, &mut known);

        let mut routes: Vec<Vec<PairData>> = vec![];

        self.dfs(
            token,
            network,
            block,
            &mut vec![],
            &mut HashSet::new(),
            &pegged_tokens,
            &hops,
            &mut routes,
        );

        for route in &mut routes {
            for hop in route {
                self.add_reserve_info(hop, block);
            }
        }

        self.with_info(routes, network, token)
    }
}

impl OnChainConfig {
    fn fetch_token_price_uncached(&self, token_address: EVMAddress) -> Option<(u32, u32)> {
        panic!("not implemented");
    }
}

impl PriceOracle for OnChainConfig {
    fn fetch_token_price(&mut self, token_address: EVMAddress) -> Option<(u32, u32)> {
        if self.price_cache.contains_key(&token_address) {
            return self.price_cache.get(&token_address).unwrap().clone();
        }
        let price = self.fetch_token_price_uncached(token_address);
        self.price_cache.insert(token_address, price);
        price
    }
}

fn get_header() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("authority", "etherscan.io".parse().unwrap());
    headers.insert("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9".parse().unwrap());
    headers.insert(
        "accept-language",
        "zh-CN,zh;q=0.9,en;q=0.8".parse().unwrap(),
    );
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
    use super::*;
    use crate::evm::onchain::endpoints::Chain::{BSC, ETH};

    #[test]
    fn test_onchain_config() {
        let mut config = OnChainConfig::new(BSC, 0);
        let v = config._request(
            "eth_getCode".to_string(),
            "[\"0x0000000000000000000000000000000000000000\", \"latest\"]".to_string(),
        );
        println!("{:?}", v)
    }

    #[test]
    fn test_get_contract_code() {
        let mut config = OnChainConfig::new(BSC, 0);
        let v = config.get_contract_code(
            EVMAddress::from_str("0x10ed43c718714eb63d5aa57b78b54704e256024e").unwrap(),
            false,
        );
        println!("{:?}", v)
    }

    #[test]
    fn test_get_contract_slot() {
        let mut config = OnChainConfig::new(BSC, 0);
        let v = config.get_contract_slot(
            EVMAddress::from_str("0xb486857fac4254a7ffb3b1955ee0c0a2b2ca75ab").unwrap(),
            EVMU256::from(3),
            false,
        );
        println!("{:?}", v)
    }

    #[test]
    fn test_fetch_abi() {
        let mut config = OnChainConfig::new(BSC, 0);
        let v = config
            .fetch_abi(EVMAddress::from_str("0xa0a2ee912caf7921eaabc866c6ef6fec8f7e90a4").unwrap());
        println!("{:?}", v)
    }

    // #[test]
    // fn test_get_pegged_next_hop() {
    //     let config = OnChainConfig::new(BSC, 22055611);
    //     let token = "0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82";
    //     let v = config.get_pegged_next_hop(token, "bsc", "latest");
    //     assert!(v.src == "pegged_weth");
    //     assert!(v.token == token);
    // }

    // #[test]
    // fn test_get_all_hops() {
    //     let config = OnChainConfig::new(BSC, 22055611);
    //     let mut known: HashSet<String> = HashSet::new();
    //     let v = config.get_all_hops(
    //         "0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82",
    //         "bsc",
    //         "latest",
    //         0,
    //         &mut known,
    //     );
    //     assert!(v.len() > 0);
    // }

    // #[test]
    // fn test_get_pair_pegged() {
    //     let config = OnChainConfig::new(BSC, 22055611);
    //     let v = config.get_pair_pegged(
    //         "0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82",
    //         "bsc",
    //         "latest",
    //     );
    //     assert!(!v.is_empty());
    // }

    // #[test]
    // fn test_get_pair() {
    //     let config = OnChainConfig::new(BSC, 22055611);
    //     let v = config.get_pair(
    //         "0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82",
    //         "bsc",
    //         "latest",
    //     );
    //     assert!(!v.is_empty());
    // }

    // #[test]
    // fn test_fetch_uniswap_path() {
    //     let config = OnChainConfig::new(BSC, 22055611);
    //     let v = config.fetch_uniswap_path(
    //         EVMAddress::from_str("0xcff086ead392ccb39c49ecda8c974ad5238452ac").unwrap(),
    //     );
    //     assert!(v.swaps.len() > 0);
    //     assert!(!v.weth_address.is_zero());
    //     assert!(!v.address.is_zero());
    // }

    // #[test]
    // fn test_fetch_token_price() {
    //     let mut config = OnChainConfig::new(BSC, 0);
    //     config.add_moralis_api_key(
    //         "ocJtTEZWOJZjYOMAQjRmWcHpvUdieMLJDAtUjycFNTdSxgFGofNJhdiRX0Kk1h1O".to_string(),
    //     );
    //     let v = config.fetch_token_price(
    //         EVMAddress::from_str("0xa0a2ee912caf7921eaabc866c6ef6fec8f7e90a4").unwrap(),
    //     );
    //     println!("{:?}", v)
    // }
    //
    // #[test]
    // fn test_fetch_storage_all() {
    //     let mut config = OnChainConfig::new(BSC, 0);
    //     let v = config.fetch_storage_all(
    //         EVMAddress::from_str("0x2aB472b185787b665f334F12618254CaCA668e49").unwrap(),
    //     );
    //     println!("{:?}", v)
    // }

    // #[test]
    // fn test_fetch_storage_dump() {
    //     let mut config = OnChainConfig::new(ETH, 0);
    //     let v = config
    //         .fetch_storage_dump(
    //             EVMAddress::from_str("0x3ea826a2724f3df727b64db552f3103192158c58").unwrap(),
    //         )
    //         .unwrap();

    //     let v0 = v.get(&EVMU256::from(0)).unwrap().clone();

    //     let slot_v = config.get_contract_slot(
    //         EVMAddress::from_str("0x3ea826a2724f3df727b64db552f3103192158c58").unwrap(),
    //         EVMU256::from(0),
    //         false,
    //     );

    //     assert_eq!(slot_v, v0);
    // }
}
