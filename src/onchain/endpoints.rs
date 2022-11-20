use bytes::Bytes;
use primitive_types::{H160, U256};
use revm::{Bytecode, LatestSpec};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt::format;
use std::str::FromStr;

#[derive(Clone, Debug, Hash, PartialEq, Eq, Copy)]
pub enum Chain {
    ETH,
    BSC,
    POLYGON,
    MUMBAI,
}

impl Chain {
    pub fn from_str(s: &String) -> Self {
        match s.as_str() {
            "ETH" => Chain::ETH,
            "BSC" => Chain::BSC,
            "POLYGON" => Chain::POLYGON,
            "MUMBAI" => Chain::MUMBAI,
            _ => panic!("Unknown chain"),
        }
    }

    pub fn get_chain_id(&self) -> u32 {
        match self {
            Chain::ETH => 1,
            Chain::BSC => 56,
            Chain::POLYGON => 137,
            Chain::MUMBAI => 80001
        }
    }

    pub fn to_lowercase(&self) -> String {
        match self {
            Chain::ETH => "eth",
            Chain::BSC => "bsc",
            Chain::POLYGON => "polygon",
            Chain::MUMBAI => "mumbai"
        }.to_string()
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

    pub etherscan_api_key: Vec<String>,
    pub etherscan_base: String,

    pub moralis_api_key: Vec<String>,
    pub moralis_handle: String,
}

impl OnChainConfig {
    pub fn new(chain: Chain, block_number: u64) -> Self {
        Self::new_raw(
            match chain {
                Chain::ETH => "https://rpc.ankr.com/eth/",
                Chain::BSC => "https://bsc-dataseed.binance.org/",
                Chain::POLYGON => "https://polygon-rpc.com/",
                Chain::MUMBAI => "https://rpc-mumbai.maticvigil.com/",
            }.to_string(),
            chain.get_chain_id(),
            block_number,
            match chain {
                Chain::ETH => "https://api.etherscan.io/api",
                Chain::BSC => "https://api.bscscan.com/api",
                Chain::POLYGON => "https://api.polygonscan.com/api",
                Chain::MUMBAI => "https://mumbai.polygonscan.com/api",
            }.to_string(),
            chain.to_lowercase()
        )
    }

    pub fn new_raw(
        endpoint_url: String, chain_id: u32, block_number: u64, etherscan_base: String, chain_name: String) -> Self {
        Self {
            endpoint_url,
            client: reqwest::blocking::Client::new(),
            chain_id,
            block_number: if block_number == 0 {
                "latest".to_string()
            } else {
                format!("0x{:x}", block_number)
            },
            etherscan_api_key: vec![],
            moralis_api_key: vec![],
            etherscan_base,
            moralis_handle: chain_name
        }
    }

    pub fn add_etherscan_api_key(&mut self, key: String) {
        self.etherscan_api_key.push(key);
    }

    pub fn add_moralis_api_key(&mut self, key: String) {
        self.moralis_api_key.push(key);
    }

    pub fn fetch_abi(&self, address: H160) -> Option<String> {
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

    fn fetch_token_price(&self, token_address: H160) -> Option<f64> {
        let endpoint = format!(
            "https://deep-index.moralis.io/api/v2/erc20/0x{}/price?chain={}",
            hex::encode(token_address),
            self.moralis_handle
        );
        println!("fetching token price from {}", endpoint);
        match self.client
            .get(endpoint.clone())
            .header("X-API-Key", if self.moralis_api_key.len() > 0 {
                self.moralis_api_key[rand::random::<usize>() % self.moralis_api_key.len()]
                    .clone()
            } else {
                "".to_string()
            })
            .send() {
            Ok(resp) => {
                let resp = resp.text();
                match resp {
                    Ok(resp) => {
                        let json = serde_json::from_str::<Value>(&resp);
                        if json.is_err() {
                            return None;
                        }
                        let result = json.unwrap()["usdPrice"].as_f64();
                        if result.is_none() {
                            return None;
                        }
                        Some(result.unwrap())
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

    fn _request(&self, method: String, params: String) -> Option<Value> {
        let data = format!(
            "{{\"jsonrpc\":\"2.0\", \"method\": \"{}\", \"params\": {}, \"id\": {}}}",
            method, params, self.chain_id
        );
        match self
            .client
            .post(self.endpoint_url.clone())
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

    pub fn get_contract_code(&self, address: H160) -> Bytecode {
        let mut params = String::from("[");
        params.push_str(&format!("\"0x{:x}\",", address));
        params.push_str(&format!("\"{}\"", self.block_number));
        params.push_str("]");
        let resp = self._request("eth_getCode".to_string(), params);
        match resp {
            Some(resp) => {
                let code = resp.as_str().unwrap();
                let code = code.trim_start_matches("0x");
                let code = hex::decode(code).unwrap();
                return Bytecode::new_raw(Bytes::from(code)).to_analysed::<LatestSpec>();
            }
            None => {
                return Bytecode::new();
            }
        }
    }

    pub fn get_contract_slot(&self, address: H160, slot: U256) -> U256 {
        let mut params = String::from("[");
        params.push_str(&format!("\"0x{:x}\",", address));
        params.push_str(&format!("\"0x{:x}\",", slot));
        params.push_str(&format!("\"{}\"", self.block_number));
        params.push_str("]");
        let resp = self._request("eth_getStorageAt".to_string(), params);
        match resp {
            Some(resp) => {
                let slot = resp.as_str().unwrap();
                let slot = slot.trim_start_matches("0x");
                let slot = hex::decode(slot).unwrap();
                return U256::from_big_endian(&slot);
            }
            None => {
                return U256::from(0);
            }
        }
    }
}

mod tests {
    use crate::onchain::endpoints::Chain::BSC;
    use super::*;

    #[test]
    fn test_onchain_config() {
        let mut config =
            OnChainConfig::new(BSC, 0);
        let v = config._request(
            "eth_getCode".to_string(),
            "[\"0x0000000000000000000000000000000000000000\", \"latest\"]".to_string(),
        );
        println!("{:?}", v)
    }

    #[test]
    fn test_get_contract_code() {
        let mut config =
            OnChainConfig::new(BSC, 0);
        let v = config.get_contract_code(
            H160::from_str("0x10ed43c718714eb63d5aa57b78b54704e256024e").unwrap(),
        );
        println!("{:?}", v)
    }

    #[test]
    fn test_get_contract_slot() {
        let mut config =
            OnChainConfig::new(BSC, 0);
        let v = config.get_contract_slot(
            H160::from_str("0xb486857fac4254a7ffb3b1955ee0c0a2b2ca75ab").unwrap(),
            U256::from(3),
        );
        println!("{:?}", v)
    }

    #[test]
    fn test_fetch_abi() {
        let mut config =
            OnChainConfig::new(BSC, 0);
        let v =
            config.fetch_abi(H160::from_str("0xa0a2ee912caf7921eaabc866c6ef6fec8f7e90a4").unwrap());
        println!("{:?}", v)
    }

    #[test]
    fn test_fetch_token_price() {
        let mut config =
            OnChainConfig::new(BSC, 0);
        config.add_moralis_api_key("[API Key]".to_string());
        let v =
            config.fetch_token_price(H160::from_str("0xa0a2ee912caf7921eaabc866c6ef6fec8f7e90a4").unwrap());
        println!("{:?}", v)
    }
}
