use glob::glob;
use serde_json::Value;
use std::collections::HashMap;
use std::fmt::format;
use std::fs::File;
use std::hash::Hash;
use std::io::Read;
use std::path::Path;
extern crate crypto;

use self::crypto::digest::Digest;
use self::crypto::sha3::Sha3;

#[derive(Debug, Clone)]
pub struct ABIConfig {
    pub abi: String,
    pub function: [u8; 4],
    pub is_static: bool,
}

#[derive(Debug, Clone)]
pub struct ContractInfo {
    pub name: String,
    pub abi: Vec<ABIConfig>,
    pub code: Vec<u8>,
    pub constructor_args: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ContractLoader {
    pub contracts: Vec<ContractInfo>,
}

pub fn set_hash(name: &str, out: &mut [u8]) {
    let mut hasher = Sha3::keccak256();
    hasher.input_str(name);
    hasher.result(out)
}

impl ContractLoader {
    fn parse_abi(path: &Path) -> Vec<ABIConfig> {
        let mut file = File::open(path).unwrap();
        let mut data = String::new();
        file.read_to_string(&mut data)
            .expect("failed to read abi file");
        let json: Vec<Value> = serde_json::from_str(&data).expect("failed to parse abi file");
        json.iter()
            .filter(|x| x["type"] == "function")
            .map(|abi| {
                let name = abi["name"].as_str().expect("failed to parse abi name");
                let mut abi_name: Vec<String> = vec![];
                abi["inputs"]
                    .as_array()
                    .expect("failed to parse abi inputs")
                    .iter()
                    .for_each(|input| {
                        abi_name.push(input["type"].as_str().unwrap().to_string());
                    });
                let mut abi_config = ABIConfig {
                    abi: format!("({})", abi_name.join(",")),
                    function: [0; 4],
                    is_static: abi["stateMutability"].as_str().unwrap() == "view",
                };
                let function_to_hash = format!("{}({})", name, abi_name.join(","));
                set_hash(function_to_hash.as_str(), &mut abi_config.function);
                abi_config
            })
            .collect()
    }

    fn parse_contract_code(path: &Path) -> Vec<u8> {
        let mut file = File::open(path).unwrap();
        let mut data = String::new();
        file.read_to_string(&mut data).unwrap();
        hex::decode(data).expect("Failed to decode contract code")
    }

    pub fn from_prefix(prefix: &str) -> Self {
        let mut result = ContractInfo {
            name: prefix.to_string(),
            abi: vec![],
            code: vec![],
            constructor_args: vec![], // todo: fill this
        };
        println!("Loading contract {}", prefix);
        for i in glob(prefix).expect("not such path for prefix") {
            match i {
                Ok(path) => {
                    if path.to_str().unwrap().ends_with(".abi") {
                        // this is an ABI file
                        result.abi = Self::parse_abi(&path);
                    } else if path.to_str().unwrap().ends_with(".bin") {
                        // this is an BIN file
                        result.code = Self::parse_contract_code(&path);
                    } else {
                        println!("Found unknown file: {:?}", path.display())
                    }
                }
                Err(e) => println!("{:?}", e),
            }
        }
        return Self {
            contracts: if result.code.len() > 0 {
                vec![result]
            } else {
                vec![]
            },
        };
    }

    // This function loads constructs Contract infos from path p
    // The organization of directory p should be
    // p
    // |- contract1.abi
    // |- contract1.bin
    // |- contract2.abi
    // |- contract2.bin
    pub fn from_glob(p: &str) -> Self {
        let mut prefix_file_count: HashMap<String, u8> = HashMap::new();
        for i in glob(p).expect("not such folder") {
            match i {
                Ok(path) => {
                    let path_str = path.to_str().unwrap();
                    if path_str.ends_with(".abi") {
                        *prefix_file_count
                            .entry(path_str.replace(".abi", "").clone())
                            .or_insert(0) += 1;
                    } else if path_str.ends_with(".bin") {
                        *prefix_file_count
                            .entry(path_str.replace(".bin", "").clone())
                            .or_insert(0) += 1;
                    } else {
                        println!("Found unknown file in folder: {:?}", path.display())
                    }
                }
                Err(e) => println!("{:?}", e),
            }
        }

        let mut contracts: Vec<ContractInfo> = vec![];
        for (prefix, count) in prefix_file_count {
            if count == 2 {
                for contract in
                    Self::from_prefix((prefix.to_owned() + &String::from('*')).as_str()).contracts
                {
                    contracts.push(contract);
                }
            }
        }

        ContractLoader { contracts }
    }
}

mod tests {
    use super::*;

    #[test]
    fn test_load() {
        let loader = ContractLoader::from_glob("demo/*");
        println!(
            "{:?}",
            loader
                .contracts
                .iter()
                .map(|x| x.name.clone())
                .collect::<Vec<String>>()
        );
    }
}
