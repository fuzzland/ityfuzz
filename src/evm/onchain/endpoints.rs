use bytes::Bytes;
use primitive_types::{H160, U256};
use revm::{Bytecode, LatestSpec};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt::{format, Debug};
use std::panic;
use std::str::FromStr;
use std::sync::Arc;

#[derive(Clone, Debug, Hash, PartialEq, Eq, Copy)]
pub enum Chain {
    ETH,
    BSC,
    POLYGON,
    MUMBAI,
}

pub trait PriceOracle: Debug {
    fn fetch_token_price(&self, token_address: H160) -> Option<(f64, u32)>;
}

impl Chain {
    pub fn from_str(s: &String) -> Option<Self> {
        match s.as_str() {
            "ETH" => Some(Self::ETH),
            "BSC" => Some(Self::BSC),
            "POLYGON" => Some(Self::POLYGON),
            "MUMBAI" => Some(Self::MUMBAI),
            _ => None,
        }
    }

    pub fn get_chain_id(&self) -> u32 {
        match self {
            Chain::ETH => 1,
            Chain::BSC => 56,
            Chain::POLYGON => 137,
            Chain::MUMBAI => 80001,
        }
    }

    pub fn to_lowercase(&self) -> String {
        match self {
            Chain::ETH => "eth",
            Chain::BSC => "bsc",
            Chain::POLYGON => "polygon",
            Chain::MUMBAI => "mumbai",
        }
        .to_string()
    }

    pub fn get_chain_rpc(&self) -> String {
        match self {
            Chain::ETH => "https://eth.llamarpc.com",
            Chain::BSC => "http://bsc.node1.infra.fuzz.land",
            Chain::POLYGON => "https://polygon-rpc.com/",
            Chain::MUMBAI => "https://rpc-mumbai.maticvigil.com/",
        }
        .to_string()
    }
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

    pub use_local_proxy: bool,
    pub local_proxy_addr: String,

    pub moralis_api_key: Vec<String>,
    pub chain_name: String,

    slot_cache: HashMap<(H160, U256), U256>,
    code_cache: HashMap<H160, Bytecode>,
    price_cache: HashMap<H160, (f64, u32)>,
    abi_cache: HashMap<H160, Option<String>>,
    storage_all_cache: HashMap<H160, Option<Arc<HashMap<String, U256>>>>,
    storage_dump_cache: HashMap<H160, Option<Arc<HashMap<U256, U256>>>>,
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
            }
            .to_string(),
            chain.to_lowercase(),
            false,
            "".to_string(),
        )
    }

    pub fn new_local_proxy(chain: Chain, block_number: u64, local_proxy_addr: String) -> Self {
        Self::new_raw(
            chain.get_chain_rpc(),
            chain.get_chain_id(),
            block_number,
            "".to_string(),
            chain.to_lowercase(),
            true,
            local_proxy_addr,
        )
    }

    pub fn new_raw(
        endpoint_url: String,
        chain_id: u32,
        block_number: u64,
        etherscan_base: String,
        chain_name: String,
        use_local_proxy: bool,
        local_proxy_addr: String,
    ) -> Self {
        Self {
            endpoint_url,
            client: reqwest::blocking::Client::new(),
            chain_id,
            block_number: if block_number == 0 {
                "latest".to_string()
            } else {
                format!("0x{:x}", block_number)
            },
            block_hash: None,
            etherscan_api_key: vec![],
            moralis_api_key: vec![],
            etherscan_base,
            use_local_proxy,
            chain_name: chain_name,
            slot_cache: Default::default(),
            code_cache: Default::default(),
            price_cache: Default::default(),
            abi_cache: Default::default(),

            local_proxy_addr,
            storage_all_cache: Default::default(),
            storage_dump_cache: Default::default(),
        }
    }

    pub fn add_etherscan_api_key(&mut self, key: String) {
        self.etherscan_api_key.push(key);
    }

    pub fn add_moralis_api_key(&mut self, key: String) {
        self.moralis_api_key.push(key);
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
        let resp = if self.use_local_proxy {
            let endpoint = format!(
                "{}/full_storage/{}/{:?}",
                self.local_proxy_addr, self.chain_name, address
            );
            match self.client.get(endpoint).send() {
                Ok(res) => Some(
                    serde_json::from_str::<Value>(&res.text().unwrap().trim().to_string())
                        .expect("Failed to parse proxy response"),
                ),
                Err(_) => None,
            }
        } else {
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
        let resp = if self.use_local_proxy {
            let endpoint = format!(
                "{}/storage_dump/{}/{:?}",
                self.local_proxy_addr, self.chain_name, address
            );
            match self.client.get(endpoint).send() {
                Ok(res) => Some(
                    serde_json::from_str::<Value>(&res.text().unwrap().trim().to_string())
                        .expect("Failed to parse proxy response"),
                ),
                Err(_) => None,
            }
        } else {
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
                for (_, v) in resp["storage"]
                    .as_object()
                    .expect("failed to convert resp to array")
                    .iter()
                {
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
        if !self.use_local_proxy {
            panic!("remote fetch for holders is not supported");
        }
        let endpoint = format!(
            "{}/holders/{}/{:?}",
            self.local_proxy_addr, self.chain_name, token_address
        );
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
        if self.use_local_proxy {
            let endpoint = format!(
                "{}/abi/{}/{:?}",
                self.local_proxy_addr, self.chain_name, address
            );
            return match self.client.get(endpoint).send() {
                Ok(res) => {
                    let data = res.text().unwrap().trim().to_string();
                    if data == "[]" {
                        None
                    } else {
                        Some(data)
                    }
                }
                Err(_) => None,
            };
        }

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

        let resp_string = if self.use_local_proxy {
            let endpoint = format!(
                "{}/bytecode/{}/{:?}/{}",
                self.local_proxy_addr, self.chain_name, address, self.block_number
            );
            match self.client.get(endpoint).send() {
                Ok(res) => {
                    let data = res.text().unwrap().trim().to_string();
                    data
                }
                Err(_) => "".to_string(),
            }
        } else {
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

        let slot_hex = format!("0x{:x}", slot);

        let resp_string = if self.use_local_proxy {
            let endpoint = format!(
                "{}/slot/{}/{:?}/{}/{}",
                self.local_proxy_addr, self.chain_name, address, slot_hex, self.block_number
            );
            match self.client.get(endpoint).send() {
                Ok(res) => {
                    let data = res.text().unwrap().trim().to_string();
                    data
                }
                Err(_) => "".to_string(),
            }
        } else {
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
}

impl PriceOracle for OnChainConfig {
    fn fetch_token_price(&self, token_address: H160) -> Option<(f64, u32)> {
        let endpoint = format!(
            "https://deep-index.moralis.io/api/v2/erc20/0x{}/price?chain={}",
            hex::encode(token_address),
            self.chain_name
        );
        println!("fetching token price from {}", endpoint);
        match self
            .client
            .get(endpoint.clone())
            .header(
                "X-API-Key",
                if self.moralis_api_key.len() > 0 {
                    self.moralis_api_key[rand::random::<usize>() % self.moralis_api_key.len()]
                        .clone()
                } else {
                    "".to_string()
                },
            )
            .send()
        {
            Ok(resp) => {
                let resp = resp.text();
                match resp {
                    Ok(resp) => {
                        let json = serde_json::from_str::<Value>(&resp);
                        if json.is_err() {
                            return None;
                        }
                        let json_v = json.unwrap();
                        let price = json_v["usdPrice"].as_f64();
                        if price.is_none() {
                            return None;
                        }
                        unsafe {
                            let decimals_res = panic::catch_unwind(|| {
                                json_v
                                    .get("nativePrice")
                                    .unwrap()
                                    .get("decimals")
                                    .unwrap()
                                    .as_u64()
                                    .unwrap();
                            });
                            if decimals_res.is_err() {
                                return None;
                            }
                        }

                        let decimals = json_v
                            .get("nativePrice")
                            .unwrap()
                            .get("decimals")
                            .unwrap()
                            .as_u64()
                            .unwrap();
                        Some((price.unwrap(), decimals as u32))
                    }
                    Err(e) => {
                        println!("{:?}", e);
                        None
                    }
                }
            }
            Err(e) => {
                println!("Error: {}", e);
                None
            }
        }
    }
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

    #[test]
    fn test_fetch_token_price() {
        let mut config = OnChainConfig::new(BSC, 0);
        config.add_moralis_api_key(
            "ocJtTEZWOJZjYOMAQjRmWcHpvUdieMLJDAtUjycFNTdSxgFGofNJhdiRX0Kk1h1O".to_string(),
        );
        let v = config.fetch_token_price(
            H160::from_str("0xa0a2ee912caf7921eaabc866c6ef6fec8f7e90a4").unwrap(),
        );
        println!("{:?}", v)
    }

    #[test]
    fn test_fetch_storage_all() {
        let mut config = OnChainConfig::new(BSC, 0);
        let v = config.fetch_storage_all(
            H160::from_str("0x2aB472b185787b665f334F12618254CaCA668e49").unwrap(),
        );
        println!("{:?}", v)
    }

    #[test]
    fn test_fetch_storage_dump() {
        let mut config = OnChainConfig::new(ETH, 0);
        let v = config
            .fetch_storage_dump(
                H160::from_str("0x3ea826a2724f3df727b64db552f3103192158c58").unwrap(),
            )
            .unwrap();

        let v0 = v.get(&U256::from(0)).unwrap().clone();

        let slot_v = config.get_contract_slot(
            H160::from_str("0x3ea826a2724f3df727b64db552f3103192158c58").unwrap(),
            U256::from(0),
            false,
        );

        assert_eq!(slot_v, v0);
    }
}
