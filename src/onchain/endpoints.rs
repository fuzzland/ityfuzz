use std::collections::HashMap;
use std::fmt::format;
use bytes::Bytes;
use primitive_types::{H160, U256};
use revm::{Bytecode, LatestSpec};
use serde_json::Value;
use std::str::FromStr;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
pub struct OnChainConfig {
    pub endpoint_url: String,
    // pub cache_len: usize,
    //
    // code_cache: HashMap<H160, Bytecode>,
    // slot_cache: HashMap<(H160, U256), U256>,
    client: reqwest::blocking::Client,
    chain_id: u32,
    block_number: String,
}

impl OnChainConfig {
    pub fn new(endpoint_url: String, chain_id: u32, block_number: u64) -> Self {
        Self {
            endpoint_url,
            // cache_len: 0,
            // code_cache: Default::default(),
            // slot_cache: Default::default(),
            client: reqwest::blocking::Client::new(),
            chain_id,
            block_number: if block_number == 0 { "latest".to_string() } else { format!("0x{:x}", block_number) },
        }
    }

    fn _request(&self, method: String, params: String) -> Option<Value> {
        let data = format!("{{\"jsonrpc\":\"2.0\", \"method\": \"{}\", \"params\": {}, \"id\": {}}}",
                       method, params, self.chain_id);
        match self.client.post(self.endpoint_url.clone()).body(data).send() {
            Ok(resp) => {
                // println!("{:?}", resp.text());
                let resp = resp.text();
                match resp {
                    Ok(resp) => {
                        // println!("{:?}", resp);
                        let json: Value = serde_json::from_str(&resp).expect("failed to parse API result");
                        return Some(json["result"].clone());
                    },
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
            },
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
            },
            None => {
                return U256::from(0);
            }
        }
    }
}

mod tests {
    use super::*;

    #[test]
    fn test_onchain_config() {
        let mut config = OnChainConfig::new("https://bsc-dataseed1.binance.org/".to_string(), 56, 0);
        let v = config._request("eth_getCode".to_string(), "[\"0x0000000000000000000000000000000000000000\", \"latest\"]".to_string());
        println!("{:?}", v)
    }

    #[test]
    fn test_get_contract_code() {
        let mut config = OnChainConfig::new("https://bsc-dataseed1.binance.org/".to_string(), 56, 0);
        let v = config.get_contract_code(H160::from_str("0x10ed43c718714eb63d5aa57b78b54704e256024e").unwrap());
        println!("{:?}", v)
    }

    #[test]
    fn test_get_contract_slot() {
        let mut config = OnChainConfig::new("https://bsc-dataseed1.binance.org/".to_string(), 56, 0);
        let v = config.get_contract_slot(H160::from_str("0xb486857fac4254a7ffb3b1955ee0c0a2b2ca75ab").unwrap(), U256::from(3));
        println!("{:?}", v)
    }
}
