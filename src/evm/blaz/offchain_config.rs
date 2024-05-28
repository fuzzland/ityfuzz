use std::{error::Error, str::FromStr};

use revm_primitives::HashMap;
use serde_json::Value;

use crate::evm::{blaz::get_client, types::EVMAddress};

pub struct OffchainContractConfig {
    pub constructor: String,
    pub address: EVMAddress,
}

// filename -> contractname -> OffchainContractConfig
pub struct OffchainConfig {
    pub configs: HashMap<(String, String), OffchainContractConfig>,
}

impl OffchainConfig {
    pub fn from_json_url(url: String) -> Result<Self, Box<dyn Error>> {
        let client = get_client();
        let resp = client.get(url).send()?;
        Self::from_json(resp.text().expect("parse json failed"))
    }

    pub fn from_file(file: String) -> Result<Self, Box<dyn Error>> {
        let json = std::fs::read_to_string(file)?;
        Self::from_json(json)
    }

    pub fn from_json(json: String) -> Result<Self, Box<dyn Error>> {
        let json = serde_json::from_str::<Value>(&json)?;
        let mut configs = HashMap::new();
        for (filename, contract) in json.as_object().expect("get contract failed") {
            let contract_obj = contract.as_object().expect("get contract failed");
            for (contract_name, config) in contract_obj {
                let config_obj = config.as_object().expect("get config failed");
                let constructor = config_obj["constructor_args"].as_str().expect("get constructor failed");
                let address = config_obj["address"].as_str().expect("get address failed");
                let address = EVMAddress::from_str(address).expect("parse address failed");
                configs.insert(
                    (filename.clone(), contract_name.clone()),
                    OffchainContractConfig {
                        constructor: constructor.to_string().trim_start_matches("0x").to_string(),
                        address,
                    },
                );
            }
        }
        Ok(Self { configs })
    }
}
