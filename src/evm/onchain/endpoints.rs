use crate::evm::uniswap::{
    get_uniswap_info, PairContext, PathContext, TokenContext, UniswapProvider,
};
use bytes::Bytes;
use primitive_types::{H160, U256};
use reqwest::header::HeaderMap;
use revm::{Bytecode, LatestSpec};
use std::collections::{HashMap, HashSet};

use serde::Deserialize;
use serde_json::{json, Value};
use std::cell::RefCell;
use std::fmt::Debug;
use std::panic;
use std::rc::Rc;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

const MAX_HOPS: u32 = 5; // Assuming the value of MAX_HOPS

#[derive(Clone, Debug, Hash, PartialEq, Eq, Copy)]
pub enum Chain {
    ETH,
    BSC,
    POLYGON,
    MUMBAI,
    LOCAL,
}

pub trait PriceOracle: Debug {
    // ret0: price = int(original_price x 10^5)
    // ret1: decimals of the token
    fn fetch_token_price(&mut self, token_address: H160) -> Option<(u32, u32)>;
}

impl Chain {
    pub fn from_str(s: &String) -> Option<Self> {
        match s.as_str() {
            "ETH" | "eth" => Some(Self::ETH),
            "BSC" | "bsc" => Some(Self::BSC),
            "POLYGON" | "polygon" => Some(Self::POLYGON),
            "MUMBAI" | "mumbai" => Some(Self::MUMBAI),
            "LOCAL" | "local" => Some(Self::LOCAL),
            _ => None,
        }
    }

    pub fn get_chain_id(&self) -> u32 {
        match self {
            Chain::ETH => 1,
            Chain::BSC => 56,
            Chain::POLYGON => 137,
            Chain::MUMBAI => 80001,
            Chain::LOCAL => 31337,
        }
    }

    pub fn to_lowercase(&self) -> String {
        match self {
            Chain::ETH => "eth",
            Chain::BSC => "bsc",
            Chain::POLYGON => "polygon",
            Chain::MUMBAI => "mumbai",
            Chain::LOCAL => "local",
        }
        .to_string()
    }

    pub fn get_chain_rpc(&self) -> String {
        match self {
            Chain::ETH => "https://eth.llamarpc.com",
            Chain::BSC => "https://bsc.llamarpc.com",
            Chain::POLYGON => "https://polygon.llamarpc.com",
            Chain::MUMBAI => "https://rpc-mumbai.maticvigil.com/",
            Chain::LOCAL => "http://localhost:8545",
        }
        .to_string()
    }
}

#[derive(Clone)]
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
    // code_cache: HashMap<H160, Bytecode>,
    // slot_cache: HashMap<(H160, U256), U256>,
    pub client: reqwest::blocking::Client,
    pub chain_id: u32,
    pub block_number: String,
    pub block_hash: Option<String>,

    pub etherscan_api_key: Vec<String>,
    pub etherscan_base: String,

    pub chain_name: String,

    slot_cache: HashMap<(H160, U256), U256>,
    code_cache: HashMap<H160, Bytecode>,
    price_cache: HashMap<H160, Option<(u32, u32)>>,
    abi_cache: HashMap<H160, Option<String>>,
    storage_all_cache: HashMap<H160, Option<Arc<HashMap<String, U256>>>>,
    storage_dump_cache: HashMap<H160, Option<Arc<HashMap<U256, U256>>>>,
    uniswap_path_cache: HashMap<H160, TokenContext>,
}

impl OnChainConfig {
    pub fn new(chain: Chain, block_number: u64) -> Self {
        Self::new_raw(
            chain.get_chain_rpc(),
            chain.get_chain_id(),
            block_number,
            match chain {
                Chain::ETH => "https://api.etherscan.io/api",
                Chain::BSC => "https://api.bscscan.com/api",
                Chain::POLYGON => "https://api.polygonscan.com/api",
                Chain::MUMBAI => "https://mumbai.polygonscan.com/api",
                Chain::LOCAL => "http://localhost:8080/abi/",
            }
            .to_string(),
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
        }
    }

    pub fn add_etherscan_api_key(&mut self, key: String) {
        self.etherscan_api_key.push(key);
    }

    pub fn get_with_retry(&self, endpoint: String) -> reqwest::blocking::Response {
        let mut retry = 0;
        loop {
            let resp = self.client.get(&endpoint).send();
            if let Ok(resp) = resp {
                if resp.status().is_success() {
                    return resp;
                }
            }
            retry += 1;
            if retry > 3 {
                panic!("get {} failed for {} retries", endpoint, retry);
            }
        }
    }

    pub fn fetch_storage_all(&mut self, address: H160) -> Option<Arc<HashMap<String, U256>>> {
        if let Some(storage) = self.storage_all_cache.get(&address) {
            return storage.clone();
        } else {
            let storage = self.fetch_storage_all_uncached(address);
            self.storage_all_cache.insert(address, storage.clone());
            storage
        }
    }

    pub fn fetch_storage_all_uncached(&self, address: H160) -> Option<Arc<HashMap<String, U256>>> {
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
                        U256::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap(),
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

    pub fn fetch_storage_dump(&mut self, address: H160) -> Option<Arc<HashMap<U256, U256>>> {
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
        address: H160,
    ) -> Option<Arc<HashMap<U256, U256>>> {
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
                if kvs.len() == 0 {
                    return None;
                }
                for (_, v) in kvs.iter() {
                    let key = v["key"].as_str().expect("fail to find key");
                    let value = v["value"].as_str().expect("fail to find value");

                    map.insert(
                        U256::from_str_radix(key.trim_start_matches("0x"), 16).unwrap(),
                        U256::from_str_radix(value.trim_start_matches("0x"), 16).unwrap(),
                    );
                }
                Some(Arc::new(map))
            }
            None => None,
        }
    }

    pub fn fetch_holders(&self, token_address: H160) -> Option<Vec<H160>> {
        panic!("remote fetch for holders is not supported");
        let endpoint = format!("{}/holders/{}/{:?}", "", self.chain_name, token_address);
        return match self.client.get(endpoint).send() {
            Ok(res) => {
                let data = res.text().unwrap().trim().to_string();
                if data == "[]" {
                    None
                } else {
                    // hacky way to parse an array of addresses
                    Some(
                        data[1..data.len() - 1]
                            .split(",")
                            .map(|x| x.trim_start_matches('"').trim_end_matches('"'))
                            .map(|x| H160::from_str(x).unwrap())
                            .collect(),
                    )
                }
            }
            Err(_) => None,
        };
    }

    pub fn fetch_abi_uncached(&self, address: H160) -> Option<String> {
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
        match self.client.get(endpoint.clone()).send() {
            Ok(resp) => {
                let resp = resp.text();
                match resp {
                    Ok(resp) => {
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
                    Err(e) => {
                        println!("{:?}", e);
                        None
                    }
                }
            }
            Err(e) => {
                println!("Error: {}", e);
                return None;
            }
        }
    }

    pub fn fetch_abi(&mut self, address: H160) -> Option<String> {
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
        match self
            .client
            .post(self.endpoint_url.clone())
            .header("Content-Type", "application/json")
            .body(data)
            .send()
        {
            Ok(resp) => {
                // println!("{:?}", resp.text());
                let resp = resp.text();
                match resp {
                    Ok(resp) => {
                        // println!("{:?}", resp);
                        let json: Value =
                            serde_json::from_str(&resp).expect("failed to parse API result");
                        return Some(json["result"].clone());
                    }
                    Err(e) => {
                        println!("{:?}", e);
                        return None;
                    }
                }
            }
            Err(e) => {
                println!("Error: {}", e);
                return None;
            }
        }
    }

    pub fn get_contract_code(&mut self, address: H160, force_cache: bool) -> Bytecode {
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
            params.push_str("]");
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
        if code.len() == 0 {
            self.code_cache.insert(address, Bytecode::new());
            return Bytecode::new();
        }
        let code = hex::decode(code).unwrap();
        let bytes = Bytecode::new_raw(Bytes::from(code)).to_analysed::<LatestSpec>();
        self.code_cache.insert(address, bytes.clone());
        return bytes;
    }

    pub fn get_contract_slot(&mut self, address: H160, slot: U256, force_cache: bool) -> U256 {
        if self.slot_cache.contains_key(&(address, slot)) {
            return self.slot_cache[&(address, slot)];
        }
        if force_cache {
            return U256::zero();
        }

        let resp_string = {
            let mut params = String::from("[");
            params.push_str(&format!("\"0x{:x}\",", address));
            params.push_str(&format!("\"0x{:x}\",", slot));
            params.push_str(&format!("\"{}\"", self.block_number));
            params.push_str("]");
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

        if slot_suffix.len() == 0 {
            self.slot_cache.insert((address, slot), U256::zero());
            return U256::zero();
        }
        let slot_value = U256::from_big_endian(&hex::decode(slot_suffix).unwrap());
        self.slot_cache.insert((address, slot), slot_value);
        return slot_value;
    }

    pub fn fetch_uniswap_path(&self, token_address: H160) -> TokenContext {
        let token = format!("{:?}", token_address);
        let info: Info = self.find_path_subgraph(&self.chain_name, &token, &self.block_number);

        let basic_info = info.basic_info;
        let weth = H160::from_str(&basic_info.weth).expect("failed to parse weth");
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
                            // let next = H160::from_str(pair["next"].as_str().expect("failed to parse next")).expect("failed to parse next");

                            path_parsed.route.push(Rc::new(RefCell::new(PairContext {
                                pair_address: H160::from_str(pair.pair.as_str())
                                    .expect("failed to parse pair"),
                                next_hop: H160::from_str(pair.next.as_str())
                                    .expect("failed to parse pair"),
                                side: pair.in_ as u8,
                                uniswap_info: Arc::new(get_uniswap_info(
                                    &UniswapProvider::from_str(pair.src_exact.as_str()).unwrap(),
                                    &Chain::from_str(&self.chain_name).unwrap(),
                                )),
                                initial_reserves: (
                                    U256::from_big_endian(
                                        &hex::decode(pair.initial_reserves_0.to_string()).unwrap(),
                                    ),
                                    U256::from_big_endian(
                                        &hex::decode(pair.initial_reserves_1.to_string()).unwrap(),
                                    ),
                                ),
                            })));
                        }
                        "pegged" => {
                            // always live at final
                            path_parsed.final_pegged_ratio = U256::from(pair.rate);
                            path_parsed.final_pegged_pair =
                                Rc::new(RefCell::new(Some(PairContext {
                                    pair_address: H160::from_str(pair.pair.as_str())
                                        .expect("failed to parse pair"),
                                    next_hop: H160::from_str(pair.next.as_str())
                                        .expect("failed to parse pair"),
                                    side: pair.in_ as u8,
                                    uniswap_info: Arc::new(get_uniswap_info(
                                        &UniswapProvider::from_str(pair.src_exact.as_str())
                                            .unwrap(),
                                        &Chain::from_str(&self.chain_name).unwrap(),
                                    )),
                                    initial_reserves: (
                                        U256::from_big_endian(
                                            &hex::decode(pair.initial_reserves_0.to_string())
                                                .unwrap(),
                                        ),
                                        U256::from_big_endian(
                                            &hex::decode(pair.initial_reserves_1.to_string())
                                                .unwrap(),
                                        ),
                                    ),
                                })));
                        }
                        "pegged_weth" => {
                            path_parsed.final_pegged_ratio = U256::from(pair.rate);
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

    pub fn fetch_uniswap_path_cached(&mut self, token: H160) -> &TokenContext {
        if self.uniswap_path_cache.contains_key(&token) {
            return self.uniswap_path_cache.get(&token).unwrap();
        }

        let path = self.fetch_uniswap_path(token);
        self.uniswap_path_cache.insert(token, path);
        self.uniswap_path_cache.get(&token).unwrap()
    }
}

impl OnChainConfig {
    fn get_pair(&self, token: &str, network: &str, block: &str) -> Vec<PairData> {
        let block_int;

        match block {
            "latest" => block_int = self.get_latest_block() - 50,
            _ => block_int = u64::from_str_radix(&block.trim_start_matches("0x"), 16).unwrap(),
        }

        let mut next_tokens: Vec<PairData> = vec![];
        let api = get_uniswap_api(network);

        if api.contains_key("v2") {
            for (name, url) in api.get("v2").unwrap() {
                let body = json!({
                    "query": format!("{{ p0: pairs(block:{{number:{}}},first:10,where :{{token0 : \"{}\"}}) {{ id token0 {{ decimals id }} token1 {{ decimals id }} }} p1: pairs(block:{{number:{}}},first:10, where :{{token1 : \"{}\"}}) {{ id token0 {{ decimals id }} token1 {{ decimals id }} }} }}", block_int, token.to_lowercase(), block_int, token.to_lowercase())
                }).to_string();

                let headers = get_header();

                let res: GetPairResponse = self
                    .client
                    .post(url.to_string())
                    .headers(headers)
                    .body(body)
                    .send()
                    .unwrap()
                    .json()
                    .unwrap();

                for pair in res.data.p0.iter().chain(res.data.p1.iter()) {
                    next_tokens.push(PairData {
                        src: "v2".to_string(),
                        in_: if pair.token0.id == *token { 0 } else { 1 },
                        pair: pair.id.to_string(),
                        next: if pair.token0.id != *token {
                            pair.token0.id.clone()
                        } else {
                            pair.token1.id.clone()
                        },
                        decimals0: pair.token0.decimals.parse().unwrap(),
                        decimals1: pair.token1.decimals.parse().unwrap(),
                        src_exact: name.to_string(),
                        rate: 0,
                        token: token.to_string(),
                        initial_reserves_0: "".to_string(),
                        initial_reserves_1: "".to_string(),
                    });
                }
            }
        }
        next_tokens
    }

    fn get_pair_pegged(&self, token: &str, network: &str, block: &str) -> Vec<PairData> {
        let block_int = if block != "latest" {
            u64::from_str_radix(&block.trim_start_matches("0x"), 16)
                .expect("failed to parse block number")
                - 50
        } else {
            self.get_latest_block() - 50
        };

        let mut next_tokens: Vec<PairData> = Vec::new();

        let api = get_uniswap_api(network);

        if api.contains_key("v2") {
            for (name, i) in &api["v2"] {
                let body = json!({
                    "query": format!("{{ p0: pairs(block:{{number:{}}},first:10,where :{{token0 : \"{}\", token1: \"{}\"}}) {{ id token0 {{ decimals id }} token1 {{ decimals id }} }} p1: pairs(block:{{number:{}}},first:10, where :{{token1 : \"{}\", token0: \"{}\"}}) {{ id token0 {{ decimals id }} token1 {{ decimals id }} }} }}", block_int, token.to_lowercase(), self.get_weth(network), block_int, token.to_lowercase(), self.get_weth(network))
                }).to_string();
                let headers = get_header();
                let res: GetPairResponse = self
                    .client
                    .post(i.to_string())
                    .headers(headers)
                    .body(body)
                    .send()
                    .unwrap()
                    .json()
                    .unwrap();

                for pair in res.data.p0.iter().chain(res.data.p1.iter()) {
                    next_tokens.push(PairData {
                        in_: if pair.token0.id == *token { 0 } else { 1 },
                        pair: pair.id.clone(),
                        next: if pair.token0.id != *token {
                            pair.token0.id.clone()
                        } else {
                            pair.token1.id.clone()
                        },
                        decimals0: pair.token0.decimals.parse().unwrap(),
                        decimals1: pair.token1.decimals.parse().unwrap(),
                        src_exact: name.to_string(),
                        src: "pegged".to_string(),
                        rate: 0,
                        token: token.to_string(),
                        initial_reserves_0: "".to_string(),
                        initial_reserves_1: "".to_string(),
                    });
                }
            }
        }

        next_tokens
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

    fn get_latest_block(&self) -> u64 {
        let block = {
            let mut params = String::from("[");
            params.push_str("]");
            let resp = self._request("eth_blockNumber".to_string(), params);
            match resp {
                Some(resp) => {
                    let data = resp.as_u64().unwrap();
                    data
                }
                None => 0,
            }
        };
        block
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
            _ => panic!("Unknown network"),
        }
    }

    fn fetch_reserve(&self, pair: &str, block: &str) -> (String, String) {
        let result = {
            let params = json!([{
            "to": pair,
            "data": "0x0902f1ac"
        }, block]);
            let resp = self._request("eth_call".to_string(), params.to_string());
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
        block: &str,
        hop: u32,
        known: &mut HashSet<String>,
    ) -> HashMap<String, Vec<PairData>> {
        known.insert(token.to_string());

        if hop > MAX_HOPS {
            return HashMap::new();
        }

        let mut hops: HashMap<String, Vec<PairData>> = HashMap::new();
        hops.insert(token.to_string(), self.get_pair(token, network, block));

        let pegged_tokens = self.get_pegged_token(network);

        for i in hops.clone().get(token).unwrap() {
            if pegged_tokens.values().any(|v| v == &i.next) || known.contains(&i.next) {
                continue;
            }
            let next_hops = self.get_all_hops(&i.next, network, block, hop + 1, known);
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
        let mut peg_info = self
            .get_pair_pegged(token, network, block)
            .get(0)
            .unwrap()
            .clone();

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
        let hops = self.get_all_hops(token, network, block, 0, &mut known);

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
    fn fetch_token_price_uncached(&self, token_address: H160) -> Option<(u32, u32)> {
            panic!("not implemented");
            panic!("not implemented");
        }
        panic!("not implemented");
        }
    }
}

impl PriceOracle for OnChainConfig {
    fn fetch_token_price(&mut self, token_address: H160) -> Option<(u32, u32)> {
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

fn get_uniswap_api(network: &str) -> HashMap<&str, HashMap<&str, &str>> {
    let mut api = HashMap::new();

    match network {
        "eth" => {
            let mut v2 = HashMap::new();
            v2.insert(
                "uniswapv2",
                "https://api.thegraph.com/subgraphs/name/uniswap/uniswap-v2",
            );
            api.insert("v2", v2);

            let mut v3 = HashMap::new();
            v3.insert(
                "uniswapv3",
                "https://api.thegraph.com/subgraphs/name/uniswap/uniswap-v3",
            );
            api.insert("v3", v3);
        }
        "bsc" => {
            let mut v2 = HashMap::new();
            v2.insert(
                "pancakeswap",
                "https://api.thegraph.com/subgraphs/name/pancakeswap/pairs",
            );
            api.insert("v2", v2);
        }
        "polygon" => {
            let mut v3 = HashMap::new();
            v3.insert(
                "uniswapv3",
                "https://api.thegraph.com/subgraphs/name/ianlapham/uniswap-v3-polygon",
            );
            api.insert("v3", v3);
        }
        "mumbai" => {}
        _ => return panic!("Unknown network"),
    }

    api
}

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
            H160::from_str("0x10ed43c718714eb63d5aa57b78b54704e256024e").unwrap(),
            false,
        );
        println!("{:?}", v)
    }

    #[test]
    fn test_get_contract_slot() {
        let mut config = OnChainConfig::new(BSC, 0);
        let v = config.get_contract_slot(
            H160::from_str("0xb486857fac4254a7ffb3b1955ee0c0a2b2ca75ab").unwrap(),
            U256::from(3),
            false,
        );
        println!("{:?}", v)
    }

    #[test]
    fn test_fetch_abi() {
        let mut config = OnChainConfig::new(BSC, 0);
        let v =
            config.fetch_abi(H160::from_str("0xa0a2ee912caf7921eaabc866c6ef6fec8f7e90a4").unwrap());
        println!("{:?}", v)
    }

    // #[test]
    // fn test_fetch_token_price() {
    //     let mut config = OnChainConfig::new(BSC, 0);
    //     config.add_moralis_api_key(
    //         "ocJtTEZWOJZjYOMAQjRmWcHpvUdieMLJDAtUjycFNTdSxgFGofNJhdiRX0Kk1h1O".to_string(),
    //     );
    //     let v = config.fetch_token_price(
    //         H160::from_str("0xa0a2ee912caf7921eaabc866c6ef6fec8f7e90a4").unwrap(),
    //     );
    //     println!("{:?}", v)
    // }
    //
    // #[test]
    // fn test_fetch_storage_all() {
    //     let mut config = OnChainConfig::new(BSC, 0);
    //     let v = config.fetch_storage_all(
    //         H160::from_str("0x2aB472b185787b665f334F12618254CaCA668e49").unwrap(),
    //     );
    //     println!("{:?}", v)
    // }

    // #[test]
    // fn test_fetch_storage_dump() {
    //     let mut config = OnChainConfig::new(ETH, 0);
    //     let v = config
    //         .fetch_storage_dump(
    //             H160::from_str("0x3ea826a2724f3df727b64db552f3103192158c58").unwrap(),
    //         )
    //         .unwrap();

    //     let v0 = v.get(&U256::from(0)).unwrap().clone();

    //     let slot_v = config.get_contract_slot(
    //         H160::from_str("0x3ea826a2724f3df727b64db552f3103192158c58").unwrap(),
    //         U256::from(0),
    //         false,
    //     );

    //     assert_eq!(slot_v, v0);
    // }
}
