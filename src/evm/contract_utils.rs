use core::panic;
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap, HashSet},
    fs::File,
    io::Read,
    ops::Deref,
    path::{Path, PathBuf},
    rc::Rc,
    str::FromStr,
    sync::RwLockReadGuard,
};

use alloy_primitives::{Address, Keccak256};
// use alloy_primitives::Bytes;
use bytes::Bytes;
use colored::Colorize;
/// Load contract from file system or remote
use glob::glob;
use itertools::Itertools;
use libafl::{schedulers::StdScheduler, state::HasMetadata};
use libafl_bolts::AsSlice;
use regex::Regex;
use revm_primitives::{bitvec::vec, Bytecode, Env};
use serde_json::Value;

use crate::{
    evm::{
        middlewares::middleware::MiddlewareType,
        onchain::abi_decompiler::fetch_abi_evmole,
        tokens::constant_pair::ConstantPairMetadata,
        types::{fixed_address, generate_random_address, EVMAddress, EVMFuzzState},
        vm::{IN_DEPLOY, SETCODE_ONLY},
        PRESET_WETH,
    },
    generic_vm::vm_executor::GenericVM,
    state::{FuzzState, HasCaller},
};

extern crate crypto;
use revm_interpreter::opcode::PUSH4;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info};

use self::crypto::{digest::Digest, sha3::Sha3};
use super::{
    abi::ABIAddressToInstanceMap,
    blaz::{is_bytecode_similar_lax, is_bytecode_similar_strict_ranking},
    corpus_initializer::{EnvMetadata, INITIAL_BALANCE},
    host::FuzzHost,
    input::ConciseEVMInput,
    middlewares::cheatcode::{Cheatcode, CHEATCODE_ADDRESS},
    types::EVMU256,
    vm::{EVMExecutor, EVMState},
};
use crate::evm::{
    abi::get_abi_type_boxed_with_address,
    blaz::{
        builder::{BuildJob, BuildJobResult},
        linking::Linker,
        offchain_artifacts::{ContractArtifact, OffChainArtifact},
        offchain_config::OffchainConfig,
    },
    bytecode_iterator::all_bytecode,
    onchain::{endpoints::OnChainConfig, OnChain},
};

// to use this address, call rand_utils::fixed_address(FIX_DEPLOYER)
pub static FIX_DEPLOYER: &str = "8b21e662154b4bbc1ec0754d0238875fe3d22fa6";
pub static FOUNDRY_DEPLOYER: &str = "1804c8AB1F12E6bbf3894d4083f33e07309d1f38";
pub static FOUNDRY_SETUP_ADDR: &str = "e1A425f1AC34A8a441566f93c82dD730639c8510";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABIConfig {
    pub abi: String,
    pub function: [u8; 4],
    pub function_name: String,
    pub is_static: bool,
    pub is_payable: bool,
    pub is_constructor: bool,
    #[serde(default)]
    pub should_add_corpus: bool,
}

#[derive(Debug, Clone)]
pub struct ContractInfo {
    pub name: String,
    pub code: Vec<u8>,
    pub abi: Vec<ABIConfig>,
    pub is_code_deployed: bool,
    pub balance: EVMU256,
    pub constructor_args: Vec<u8>,
    pub deployed_address: EVMAddress,
    pub build_artifact: Option<BuildJobResult>,
    pub files: Vec<(String, String)>, // (filename, content)
    pub source_map_replacements: Option<Vec<(String, String)>>,
    pub raw_source_map: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ABIInfo {
    pub source: String,
    pub abi: Vec<ABIConfig>,
}

#[derive(Debug, Clone)]
pub struct ContractLoader {
    pub contracts: Vec<ContractInfo>,
    pub abis: Vec<ABIInfo>,
    pub setup_data: Option<SetupData>,
}

impl ContractLoader {
    pub fn force_abi(&mut self, mapping: HashMap<String, String>) {
        for (filename_or_address, abi) in mapping {
            let mut addr = None;
            if filename_or_address.starts_with("0x") {
                addr = EVMAddress::from_str(&filename_or_address).map(Some).unwrap_or(None);
            }

            for contract in &mut self.contracts {
                if contract.name == filename_or_address ||
                    (addr.is_some() && contract.deployed_address == addr.unwrap())
                {
                    debug!("Forcing ABI for {}", contract.name);
                    contract.abi = ContractLoader::parse_abi_str(&abi);
                }
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct SetupData {
    pub evmstate: EVMState,
    pub env: Env,
    pub code: HashMap<EVMAddress, Bytes>,

    // Foundry specific
    pub excluded_contracts: Vec<EVMAddress>,
    pub excluded_senders: Vec<EVMAddress>,
    pub target_contracts: Vec<EVMAddress>,
    pub target_senders: Vec<EVMAddress>,
    pub target_selectors: HashMap<EVMAddress, Vec<Vec<u8>>>,

    // Flashloan specific
    pub v2_pairs: Vec<EVMAddress>,
    pub constant_pairs: Vec<ConstantPairMetadata>,

    pub onchain_middleware: Option<OnChain>,
}

impl Clone for SetupData {
    fn clone(&self) -> Self {
        Self {
            evmstate: self.evmstate.clone(),
            env: self.env.clone(),
            code: self.code.clone(),
            excluded_contracts: self.excluded_contracts.clone(),
            excluded_senders: self.excluded_senders.clone(),
            target_contracts: self.target_contracts.clone(),
            target_senders: self.target_senders.clone(),
            target_selectors: self.target_selectors.clone(),
            v2_pairs: self.v2_pairs.clone(),
            constant_pairs: self.constant_pairs.clone(),
            onchain_middleware: self.onchain_middleware.clone(),
        }
    }
}

pub fn set_hash(name: &str, out: &mut [u8]) {
    let mut hasher = Sha3::keccak256();
    hasher.input_str(name);
    hasher.result(out)
}

fn parse_and_convert(input: &str) -> String {
    let parts: Vec<&str> = input.trim().split_whitespace().collect();
    if parts.len() != 2 && (parts[1] != "wei" || parts[1] != "gwei" || parts[1] != "ether") {
        return 0.to_string();
    }

    let number = match u128::from_str(parts[0]) {
        Ok(num) => num,
        Err(_) => return 0.to_string(),
    };

    let value = match parts[1].to_lowercase().as_str() {
        "wei" => number,
        "gwei" => number.checked_mul(10u128.pow(9)).unwrap_or(0),
        "ether" => number.checked_mul(10u128.pow(18)).unwrap_or(0),
        _ => 0,
    }
    .to_string();
    value
}

impl ContractLoader {
    fn parse_abi(path: &Path) -> Vec<ABIConfig> {
        let mut file = File::open(path).unwrap();
        let mut data = String::new();
        file.read_to_string(&mut data).expect("failed to read abis file");
        Self::parse_abi_str(&data)
    }

    fn process_input(ty: String, input: &Value) -> String {
        if let Some(slot) = input.get("components") {
            if ty == "tuple" {
                let v = slot
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| Self::process_input(v["type"].as_str().unwrap().to_string(), v))
                    .collect::<Vec<String>>()
                    .join(",");
                return format!("({})", v);
            } else if ty.ends_with("[]") {
                return format!("{}[]", Self::process_input(ty[..ty.len() - 2].to_string(), input));
            } else if ty.ends_with(']') && ty.contains('[') {
                let split = ty.rsplit_once('[').unwrap();
                let name = split.0.to_string();
                let len = split
                    .1
                    .split(']')
                    .next()
                    .unwrap()
                    .parse::<usize>()
                    .expect("invalid array length");
                return format!("{}[{}]", Self::process_input(name, input), len);
            }
            panic!("unknown type: {}", ty);
        } else {
            ty
        }
    }

    pub fn parse_abi_str(data: &str) -> Vec<ABIConfig> {
        let json: Vec<Value> = serde_json::from_str(&Self::normalize_abi_str(data)).expect("failed to parse abis file");
        json.iter()
            .flat_map(|abi| {
                if abi["type"] == "function" || abi["type"] == "constructor" {
                    let name = if abi["type"] == "function" {
                        abi["name"].as_str().expect("failed to parse abis name")
                    } else {
                        "constructor"
                    };
                    let mut abi_name: Vec<String> = vec![];
                    abi["inputs"]
                        .as_array()
                        .expect("failed to parse abis inputs")
                        .iter()
                        .for_each(|input| {
                            abi_name.push(Self::process_input(input["type"].as_str().unwrap().to_string(), input));
                        });
                    let mut abi_config = ABIConfig {
                        abi: format!("({})", abi_name.join(",")),
                        function: [0; 4],
                        function_name: name.to_string(),
                        is_static: abi["stateMutability"] == "view",
                        is_payable: abi["stateMutability"] == "payable",
                        is_constructor: abi["type"] == "constructor",
                        should_add_corpus: true, // delaying determination of this to later
                    };
                    let function_to_hash = format!("{}({})", name, abi_name.join(","));
                    // print name and abi_name

                    set_hash(function_to_hash.as_str(), &mut abi_config.function);
                    Some(abi_config)
                } else if abi["type"] == "receive" && abi["stateMutability"] == "payable" {
                    Some(ABIConfig {
                        abi: String::from("()"),
                        function: [0; 4],
                        function_name: String::from("!receive!"),
                        is_static: false,
                        is_payable: true,
                        is_constructor: false,
                        should_add_corpus: true,
                    })
                } else if abi["type"] == "fallback" {
                    Some(ABIConfig {
                        abi: String::from("(bytes)"),
                        function: [0; 4],
                        function_name: String::from("!fallback!"),
                        is_static: false,
                        is_payable: abi["stateMutability"] == "payable",
                        is_constructor: false,
                        should_add_corpus: true,
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    fn normalize_abi_str(data: &str) -> String {
        data.to_string()
            .replace('\'', "\"")
            .replace("False", "false")
            .replace("True", "true")
    }

    fn parse_hex_file(path: &Path) -> Vec<u8> {
        let mut file = File::open(path).unwrap();
        let mut data = String::new();
        file.read_to_string(&mut data).unwrap();
        hex::decode(data.trim()).expect("Failed to parse hex file")
    }

    fn constructor_args_encode(constructor_args: &[String]) -> Vec<u8> {
        constructor_args
            .iter()
            .flat_map(|arg| {
                let arg = if let Some(stripped) = arg.strip_prefix("0x") {
                    stripped
                } else {
                    arg
                };
                let arg = if arg.len() % 2 == 1 {
                    format!("0{}", arg)
                } else {
                    arg.to_string()
                };
                let mut decoded = hex::decode(arg).unwrap();
                let len = decoded.len();
                if len < 32 {
                    let mut padding = vec![0; 32 - len]; // Create a vector of zeros
                    padding.append(&mut decoded); // Append the original vector to it
                    padding
                } else {
                    decoded
                }
            })
            .collect()
    }

    pub fn from_prefix(
        prefix: &str,
        state: &mut EVMFuzzState,
        proxy_deploy_codes: &Vec<String>,
        constructor_args: &[String],
        files: Vec<(String, String)>,
        source_map_replacements: Option<Vec<(String, String)>>,
        raw_source_maps: HashMap<String, String>, // contract name -> raw source map
    ) -> Self {
        let contract_name = prefix.split('/').last().unwrap().replace('*', "");
        // number ether, number wei, number gwei
        let contract_balance = if !constructor_args.is_empty() {
            let bal: String = constructor_args.last().unwrap().to_owned();
            if bal.ends_with("wei") || bal.ends_with("gwei") || bal.ends_with("ether") {
                EVMU256::from_str(parse_and_convert(bal.as_str()).as_str()).unwrap()
            } else {
                EVMU256::from(0)
            }
        } else {
            EVMU256::from(0)
        };

        let mut real_constructor_args = constructor_args.to_owned();

        if !constructor_args.is_empty() &&
            (constructor_args[constructor_args.len() - 1].ends_with("wei") ||
                constructor_args[constructor_args.len() - 1].ends_with("gwei") ||
                constructor_args[constructor_args.len() - 1].ends_with("ether"))
        {
            real_constructor_args.remove(constructor_args.len() - 1);
        }

        // get constructor args
        let constructor_args_in_bytes: Vec<u8> = Self::constructor_args_encode(&real_constructor_args);

        // create dummy contract info
        let mut contract_result = ContractInfo {
            name: prefix.to_string(),
            code: vec![],
            abi: vec![],
            is_code_deployed: false,
            constructor_args: constructor_args_in_bytes,
            deployed_address: generate_random_address(state),
            build_artifact: None,
            files,
            source_map_replacements,
            raw_source_map: raw_source_maps.get(&contract_name).cloned(),
            balance: contract_balance,
        };
        let mut abi_result = ABIInfo {
            source: prefix.to_string(),
            abi: vec![],
        };

        debug!("Loading contract {}", prefix);

        // Load contract, ABI, and address from file
        for i in glob(prefix).expect("not such path for prefix") {
            match i {
                Ok(path) => {
                    if path.to_str().unwrap().ends_with(".abi") {
                        // this is an ABI file
                        abi_result.abi = Self::parse_abi(&path);
                        contract_result.abi = abi_result.abi.clone();
                        // debug!("ABI: {:?}", result.abis);
                    } else if path.to_str().unwrap().ends_with(".bin") {
                        // this is an BIN file
                        contract_result.code = Self::parse_hex_file(&path);
                    } else if path.to_str().unwrap().ends_with(".address") {
                        // this is deployed address
                        contract_result
                            .deployed_address
                            .0
                            .clone_from_slice(Self::parse_hex_file(&path).as_slice());
                    } else {
                        debug!("Found unknown file: {:?}", path.display())
                    }
                }
                Err(e) => error!("{:?}", e),
            }
        }

        if let Some(abi) = abi_result.abi.iter().find(|abi| abi.is_constructor) {
            let mut abi_instance = get_abi_type_boxed_with_address(&abi.abi, fixed_address(FIX_DEPLOYER).0.to_vec());
            abi_instance.set_func_with_signature(abi.function, &abi.function_name, &abi.abi);
            if contract_result.constructor_args.is_empty() {
                debug!("No constructor args found, using default constructor args");
                contract_result.constructor_args = abi_instance.get().get_bytes();
            }
            // debug!("Constructor args: {:?}", result.constructor_args);
            // set constructor args balance
            contract_result.code.extend(contract_result.constructor_args.clone());
        } else {
            debug!("No constructor in ABI found, skipping");
        }

        // now check if contract is deployed through proxy by checking function
        // signatures if it is, then we use the new bytecode from proxy
        // todo: find a better way to do this
        let current_code = hex::encode(&contract_result.code);
        for deployed_code in proxy_deploy_codes {
            // if deploy_code startwiths '0x' then remove it
            let deployed_code = if let Some(stripped) = deployed_code.strip_prefix("0x") {
                stripped
            } else {
                deployed_code
            };

            // match all function signatures, compare sigs between our code and deployed
            // code from proxy
            let deployed_code_sig: Vec<[u8; 4]> = extract_sig_from_contract(deployed_code);
            let current_code_sig: Vec<[u8; 4]> = extract_sig_from_contract(&current_code);

            // compare deployed_code_sig and current_code_sig
            if deployed_code_sig.len() == current_code_sig.len() {
                let mut is_match = true;
                for i in 0..deployed_code_sig.len() {
                    if deployed_code_sig[i] != current_code_sig[i] {
                        is_match = false;
                        break;
                    }
                }
                if is_match {
                    contract_result.code = hex::decode(deployed_code).expect("Failed to parse deploy code");
                }
            }
        }
        Self {
            contracts: if !contract_result.code.is_empty() {
                vec![contract_result]
            } else {
                vec![]
            },
            abis: vec![abi_result],
            setup_data: None,
        }
    }

    // This function loads constructs Contract infos from path p
    // The organization of directory p should be
    // p
    // |- contract1.abi
    // |- contract1.bin
    // |- contract2.abi
    // |- contract2.bin
    pub fn from_glob(
        p: &str,
        state: &mut EVMFuzzState,
        proxy_deploy_codes: &Vec<String>,
        constructor_args_map: &HashMap<String, Vec<String>>,
        base_path: String,
        additional_path: Option<String>,
    ) -> Self {
        let mut prefix_file_count: HashMap<String, u8> = HashMap::new();
        let mut contract_combined_json_info = None;
        for i in glob(p).expect("not such folder") {
            match i {
                Ok(path) => {
                    let path_str = path.to_str().unwrap();
                    if path_str.ends_with(".abi") {
                        // skip FuzzLand.abi
                        if path_str.ends_with("FuzzLand.abi") {
                            continue;
                        }
                        *prefix_file_count
                            .entry(path_str.replace(".abi", "").clone())
                            .or_insert(0) += 1;
                    } else if path_str.ends_with(".bin") {
                        // skip FuzzLand.bin
                        if path_str.ends_with("FuzzLand.bin") {
                            continue;
                        }
                        *prefix_file_count
                            .entry(path_str.replace(".bin", "").clone())
                            .or_insert(0) += 1;
                    } else if path_str.ends_with("combined.json") {
                        contract_combined_json_info = Some(path_str.to_string());
                    } else {
                        debug!("Found unknown file in folder: {:?}", path.display())
                    }
                }
                Err(e) => error!("{:?}", e),
            }
        }

        let (files, source_map_replacements, raw_sourcemaps) = match contract_combined_json_info {
            Some(json_filename) => {
                let mut json_file = File::open(json_filename).unwrap();
                let mut buf = String::new();
                json_file.read_to_string(&mut buf).unwrap();

                extract_combined_json(buf, base_path, additional_path)
            }
            None => (vec![], None, HashMap::new()),
        };

        let mut contracts: Vec<ContractInfo> = vec![];
        let mut abis: Vec<ABIInfo> = vec![];
        for (prefix, count) in prefix_file_count.iter().sorted_by_key(|(k, _)| <&String>::clone(k)) {
            let p = prefix.to_string();
            if *count > 0 {
                let mut constructor_args: Vec<String> = vec![];
                for (k, v) in constructor_args_map.iter() {
                    let components: Vec<&str> = p.split('/').collect();
                    if let Some(last_component) = components.last() {
                        if last_component == k {
                            constructor_args = v.clone();
                        }
                    }
                }

                let prefix_loader = Self::from_prefix(
                    (prefix.to_owned() + &String::from('*')).as_str(),
                    state,
                    proxy_deploy_codes,
                    &constructor_args,
                    files.clone(),
                    source_map_replacements.clone(),
                    raw_sourcemaps.clone(),
                );
                prefix_loader.contracts.iter().for_each(|c| contracts.push(c.clone()));
                prefix_loader.abis.iter().for_each(|a| abis.push(a.clone()));
            }
        }

        ContractLoader {
            contracts,
            abis,
            setup_data: None,
        }
    }

    pub fn from_address(onchain: &mut OnChainConfig, address: HashSet<EVMAddress>, builder: Option<BuildJob>) -> Self {
        let mut contracts: Vec<ContractInfo> = vec![];
        let mut abis: Vec<ABIInfo> = vec![];
        let mut setup_data: SetupData = Default::default();

        {
            // get block number and timestamp
            let block_number = EVMU256::from_str_radix(onchain.block_number.trim_start_matches("0x"), 16).unwrap();
            let timestamp = onchain.fetch_blk_timestamp();
            let mut env = Env::default();
            env.block.number = block_number;
            env.block.timestamp = timestamp;
            setup_data.env = env;
        }

        for addr in address {
            let mut abi = None;
            let mut bytecode = None;
            let mut build_artifact = None;

            if let Some(builder) = builder.clone() {
                let result = builder.onchain_job(onchain.chain_name.clone(), addr);
                if let Some(result) = result {
                    abi = Some(result.abi.clone());
                    bytecode = Some(onchain.get_contract_code(addr, false));
                    build_artifact = Some(result);
                }
            }

            if abi.is_none() || bytecode.is_none() {
                abi = onchain.fetch_abi(addr);
                bytecode = Some(onchain.get_contract_code(addr, false));
            }

            let contract_code = bytecode.expect("Failed to get bytecode");

            let abi_parsed = if let Some(abi) = abi {
                Self::parse_abi_str(&abi)
            } else {
                debug!("ABI not found for {}, we'll decompile", addr);
                vec![]
            };

            let (files, source_map_replacements, raw_source_map) = if let Some(job_result) = build_artifact.clone() {
                (
                    job_result.sources.clone(),
                    Some(job_result.source_maps_replacements.clone()),
                    Some(job_result.source_maps.clone()),
                )
            } else {
                (vec![], None, None)
            };

            contracts.push(ContractInfo {
                name: format!("{:?}", addr),
                code: hex::decode(&contract_code).unwrap(),
                abi: abi_parsed.clone(),
                is_code_deployed: true,
                constructor_args: vec![], // todo: fill this
                deployed_address: addr,
                build_artifact,
                files,
                source_map_replacements,
                raw_source_map,
                balance: EVMU256::from(0),
            });
            abis.push(ABIInfo {
                source: addr.to_string(),
                abi: abi_parsed,
            });
            println!("Contract loaded: {:?}", addr);
        }
        Self {
            contracts,
            abis,
            setup_data: Some(setup_data),
        }
    }

    pub fn from_config(offchain_artifacts: &Vec<OffChainArtifact>, offchain_config: &OffchainConfig) -> Self {
        let mut contracts: Vec<ContractInfo> = vec![];
        let mut abis: Vec<ABIInfo> = vec![];
        for (slug, contract_info) in &offchain_config.configs {
            let mut more_info = None;
            let mut sources = None;

            for artifact in offchain_artifacts {
                if artifact.contracts.contains_key(slug) {
                    more_info = Some(artifact.contracts.get(slug).unwrap().clone());
                    sources = Some(artifact.sources.clone()); // <- todo: this is not correct
                    break;
                }
            }

            let more_info = more_info.expect("Failed to find contract info");
            let sources = sources.expect("Failed to find sources");
            let abi = Self::parse_abi_str(&more_info.abi);

            abis.push(ABIInfo {
                source: format!("{}:{}", slug.0, slug.1),
                abi: abi.clone(),
            });

            let constructor_args = hex::decode(contract_info.constructor.clone()).expect("failed to decode hex");
            contracts.push(ContractInfo {
                name: format!("{}:{}", slug.0, slug.1),
                code: [more_info.deploy_bytecode.to_vec(), constructor_args.clone()].concat(),
                abi,
                is_code_deployed: false,
                constructor_args,
                deployed_address: contract_info.address,
                build_artifact: Some(BuildJobResult::new(
                    sources.clone(),
                    more_info.source_map.clone(),
                    more_info.deploy_bytecode,
                    more_info.abi.clone(),
                    more_info.source_map_replacements.clone(),
                    // TODO: offchain ast
                    Vec::new(),
                )),
                files: sources,
                source_map_replacements: Some(more_info.source_map_replacements),
                raw_source_map: Some(more_info.source_map.clone()),
                balance: EVMU256::from(0),
            });
        }

        Self {
            contracts,
            abis,
            setup_data: None,
        }
    }

    /// This function is used to find the contract artifact from offchain
    /// artifacts by comparing the bytecode It will return the index of the
    /// artifact and the location of the contract
    fn find_contract_artifact(to_find: Vec<u8>, offchain_artifacts: &[OffChainArtifact]) -> (usize, (String, String)) {
        let mut candidates = vec![];
        let mut all_candidates = vec![];
        for (idx, artifact) in offchain_artifacts.iter().enumerate() {
            for (loc, contract) in &artifact.contracts {
                if contract.deploy_bytecode.is_empty() {
                    let contract_deploy_bytecode = hex::decode(contract.deploy_bytecode_str.as_str()).unwrap();
                    if is_bytecode_similar_lax(to_find.clone(), contract_deploy_bytecode) < 2 {
                        candidates.push((idx, loc.clone()));
                    }
                } else {
                    if is_bytecode_similar_lax(to_find.clone(), contract.deploy_bytecode.to_vec()) < 2 {
                        candidates.push((idx, loc.clone()));
                    }
                }

                all_candidates.push((idx, loc.clone()));
            }
        }
        if candidates.is_empty() {
            candidates = all_candidates;
        }

        let diffs = candidates
            .iter()
            .map(|(idx, loc)| {
                let artifact = &offchain_artifacts[*idx].contracts[loc];
                is_bytecode_similar_strict_ranking(to_find.clone(), artifact.deploy_bytecode.to_vec())
            })
            .collect::<Vec<_>>();

        let mut min_diff = usize::MAX;
        let mut selected_idx = 0;

        for (idx, diff) in diffs.iter().enumerate() {
            if *diff < min_diff {
                min_diff = *diff;
                selected_idx = idx;
            }
        }

        let (idx, loc) = candidates[selected_idx].clone();
        (idx, loc)
    }

    pub fn from_fork(
        offchain_artifacts: &Vec<OffChainArtifact>,
        onchain: &mut OnChainConfig,
        targets: HashSet<EVMAddress>,
    ) -> Self {
        let mut contracts: Vec<ContractInfo> = vec![];
        let mut abis: Vec<ABIInfo> = vec![];

        for artifact in offchain_artifacts {
            for (slug, contract_artifact) in &artifact.contracts {
                let abi = Self::parse_abi_str(&contract_artifact.abi);
                abis.push(ABIInfo {
                    source: format!("{}:{}", slug.0, slug.1),
                    abi: abi.clone(),
                });
            }
        }

        for addr in targets {
            let contract_code = onchain.get_contract_code(addr, false);
            let (artifact_idx, slug) =
                Self::find_contract_artifact(hex::decode(&contract_code).unwrap(), offchain_artifacts);

            debug!(
                "Contract at address {:?} is {:?}. If this is not correct, please log an issue on GitHub",
                addr, slug
            );

            let artifact = &offchain_artifacts[artifact_idx];
            let more_info = &artifact.contracts[&slug];

            let abi: Vec<ABIConfig> = Self::parse_abi_str(&more_info.abi);

            contracts.push(ContractInfo {
                name: format!("{:?}", addr),
                code: hex::decode(&contract_code).unwrap(),
                abi,
                is_code_deployed: true,
                constructor_args: vec![],
                deployed_address: addr,
                build_artifact: Some(BuildJobResult::new(
                    artifact.sources.clone(),
                    more_info.source_map.clone(),
                    more_info.deploy_bytecode.clone(),
                    more_info.abi.clone(),
                    more_info.source_map_replacements.clone(),
                    // TODO: offchain ast
                    Vec::new(),
                )),
                files: artifact.sources.clone(),
                source_map_replacements: Some(more_info.source_map_replacements.clone()),
                raw_source_map: Some(more_info.source_map.clone()),
                balance: EVMU256::from(0),
            });
        }
        Self {
            contracts,
            abis,
            setup_data: None,
        }
    }

    pub fn from_setup(
        offchain_artifacts: &Vec<OffChainArtifact>,
        setup_file: String,
        work_dir: String,
        etherscan_api_key: &str,
    ) -> Self {
        let mut contracts: Vec<ContractInfo> = vec![];
        let mut abis: Vec<ABIInfo> = vec![];
        for artifact in offchain_artifacts {
            for (slug, contract_artifact) in &artifact.contracts {
                let abi = Self::parse_abi_str(&contract_artifact.abi);
                abis.push(ABIInfo {
                    source: format!("{}:{}", slug.0, slug.1),
                    abi: abi.clone(),
                });
            }
        }

        let mut all_slugs = vec![];
        let mut all_matched_slugs = vec![];
        let mut setup_data = None;
        for artifact in offchain_artifacts {
            for ((filename, contract_name), contract_artifact) in &artifact
                .contracts
                .iter()
                .filter(|((s, _), _)| !s.starts_with("lib/") && !s.starts_with("hardhat/"))
                .collect::<Vec<_>>()
            {
                let slug = format!("{filename}:{contract_name}");
                all_slugs.push(slug.clone());

                if slug.contains(&setup_file) {
                    all_matched_slugs.push(slug.clone());
                }
            }
        }

        if all_matched_slugs.is_empty() {
            let all_files = all_slugs
                .iter()
                .map(|s| format!("- {}", s))
                .collect::<Vec<String>>()
                .join("\n");
            panic!(
                "Deployment script {} not found. Available contracts: \n{}",
                setup_file, all_files
            );
        } else if all_matched_slugs.len() > 1 {
            let all_files = all_matched_slugs
                .iter()
                .map(|s| format!("- {}", s))
                .collect::<Vec<String>>()
                .join("\n");
            panic!(
                "More than one contract found matching the provided deployment script pattern {}: \n{}",
                setup_file, all_files
            );
        }

        let setup_file = all_matched_slugs[0].clone();
        // find all libs
        let libs = Linker::find_all_libs_in_offchain_artifacts(offchain_artifacts).unwrap();
        // link inner libs
        let libs_linked = if !libs.is_empty() {
            Linker::link_libs_inner_lib(Some(libs)).unwrap()
        } else {
            BTreeMap::default()
        };

        let mut linked_offchain_artifacts = offchain_artifacts.clone();

        'artifacts: for (index, artifact) in offchain_artifacts.iter().enumerate() {
            for ((filename, contract_name), contract_artifact) in &artifact.contracts {
                let slug = format!("{filename}:{contract_name}");
                all_slugs.push(slug.clone());
                if slug.contains(&setup_file) {
                    let contract_artifact_linked =
                        Linker::link_setup_target_with_compute_address(&libs_linked, contract_artifact.clone())
                            .unwrap();
                    linked_offchain_artifacts[index]
                        .contracts
                        .get_mut(&(filename.clone(), contract_name.clone()))
                        .unwrap()
                        .deploy_bytecode = contract_artifact_linked.deploy_bytecode.clone();
                    setup_data = Some(Self::call_setup(
                        contract_artifact_linked.deploy_bytecode_str.clone(),
                        work_dir.clone(),
                        etherscan_api_key,
                        Some(libs_linked.clone()),
                    ));
                    break 'artifacts;
                }
            }
        }

        let mut known_addr = HashSet::new();

        if let Some(onchain) = setup_data.clone().unwrap().onchain_middleware {
            debug!("Adding onchain middleware");
            let mut onchain_config = onchain.endpoint.clone();

            for addr in setup_data.clone().unwrap().target_contracts {
                if known_addr.contains(&addr) || addr == fixed_address(FOUNDRY_SETUP_ADDR) {
                    continue;
                }
                known_addr.insert(addr);
                let code = onchain_config.get_contract_code(addr, false);
                if code.is_empty() {
                    error!("Failed to get code for contract at address {:?}", addr);
                    continue;
                }
                let code_bytes = hex::decode(&code).expect("code is not hex");
                let abi = match onchain_config.fetch_abi(addr) {
                    Some(abi_str) => Self::parse_abi_str(&abi_str),
                    None => fetch_abi_evmole(&code_bytes),
                };

                contracts.push(ContractInfo {
                    name: format!("{}", addr),
                    code: code_bytes,
                    abi: abi.clone(),
                    is_code_deployed: true,
                    constructor_args: vec![],
                    deployed_address: addr,
                    build_artifact: None,
                    files: vec![],
                    source_map_replacements: None,
                    raw_source_map: None,
                    balance: EVMU256::from(0),
                });

                abis.push(ABIInfo {
                    source: format!("{}", addr),
                    abi,
                });
            }
        }

        // update libs
        for (index, offchain_art) in offchain_artifacts.iter().enumerate() {
            for (contract_key, contract) in &offchain_art.contracts {
                if libs_linked.contains_key(contract_key) {
                    linked_offchain_artifacts[index]
                        .contracts
                        .get_mut(contract_key)
                        .unwrap()
                        .deploy_bytecode = contract.deploy_bytecode.clone();
                }
            }
        }

        // link all contracts
        linked_offchain_artifacts = Linker::link_all_contract(&linked_offchain_artifacts, libs_linked);

        for (addr, code) in setup_data.clone().unwrap().code {
            if known_addr.contains(&addr) {
                continue;
            }

            known_addr.insert(addr);
            let (artifact_idx, slug) = Self::find_contract_artifact(code.to_vec(), &linked_offchain_artifacts);

            debug!(
                "Contract at address {:?} is {:?}. If this is not correct, please log an issue on GitHub",
                addr, slug
            );
            let artifact = &linked_offchain_artifacts[artifact_idx];
            let more_info = &artifact.contracts[&slug];

            let abi: Vec<ABIConfig> = Self::parse_abi_str(&more_info.abi);

            contracts.push(ContractInfo {
                name: format!("{}:{}", slug.0, slug.1),
                code: code.to_vec(),
                abi,
                is_code_deployed: true,
                constructor_args: vec![],
                deployed_address: addr,
                build_artifact: Some(BuildJobResult::new(
                    artifact.sources.clone(),
                    more_info.source_map.clone(),
                    more_info.deploy_bytecode.clone(),
                    more_info.abi.clone(),
                    more_info.source_map_replacements.clone(),
                    // TODO: offchain ast
                    Vec::new(),
                )),
                files: artifact.sources.clone(),
                source_map_replacements: Some(more_info.source_map_replacements.clone()),
                raw_source_map: Some(more_info.source_map.clone()),
                balance: EVMU256::from(0),
            });
        }

        Self {
            contracts,
            abis,
            setup_data,
        }
    }

    fn get_vm_with_cheatcode(
        deployer: EVMAddress,
        work_dir: String,
        etherscan_api_key: &str,
    ) -> (
        EVMExecutor<EVMState, ConciseEVMInput, StdScheduler<EVMFuzzState>>,
        EVMFuzzState,
    ) {
        let mut state: EVMFuzzState = FuzzState::new(0);
        let mut executor = EVMExecutor::new(
            FuzzHost::new(StdScheduler::new(), work_dir),
            deployer, // todo: change to foundry default address
        );
        executor.host.set_code(
            CHEATCODE_ADDRESS,
            Bytecode::new_raw(Bytes::from(vec![0xfd, 0x00])),
            &mut state,
        );
        executor
            .host
            .add_middlewares(Rc::new(RefCell::new(Cheatcode::new(etherscan_api_key))));

        // Initialize state
        state
            .metadata_map_mut()
            .insert::<ABIAddressToInstanceMap>(ABIAddressToInstanceMap::new());
        state.metadata_map_mut().insert::<EnvMetadata>(EnvMetadata::default());
        let default_callers = HashSet::from([
            fixed_address("8EF508Aca04B32Ff3ba5003177cb18BfA6Cd79dd"),
            fixed_address("35c9dfd76bf02107ff4f7128Bd69716612d31dDb"),
            // fixed_address("5E6B78f0748ACd4Fb4868dF6eCcfE41398aE09cb"),
        ]);
        for caller in default_callers {
            state.add_caller(&caller);
            executor
                .host
                .evmstate
                .set_balance(caller, EVMU256::from(INITIAL_BALANCE));
        }

        (executor, state)
    }

    /// Deploy the contract and invoke "setUp()", returns the code, state, and
    /// environment after deployment. Foundry VM Cheatcodes and Hardhat
    /// consoles are enabled here.
    fn call_setup(
        deploy_code_str: String,
        work_dir: String,
        etherscan_api_key: &str,
        _libs: Option<BTreeMap<(String, String), ContractArtifact>>,
    ) -> SetupData {
        let deployer = EVMAddress::from_str(FOUNDRY_DEPLOYER).unwrap();
        let deployed_addr = EVMAddress::from_str(FOUNDRY_SETUP_ADDR).unwrap();

        let (mut evm_executor, mut state) = Self::get_vm_with_cheatcode(deployer, work_dir, etherscan_api_key);

        // deploy contract
        unsafe {
            SETCODE_ONLY = true;
        }
        // Deploy preset WETH
        let weth_addr = EVMAddress::from_str(PRESET_WETH).unwrap();
        let hex_code = include_str!("../../tests/presets/v2_pair/WETH9.bytecode").trim();
        let weth_code = Bytes::from(hex::decode(hex_code).unwrap());
        let deployed_weth = evm_executor.deploy(Bytecode::new_raw(weth_code), None, weth_addr, &mut state);
        assert!(deployed_weth.is_some(), "failed to deploy WETH");

        // deploy libs
        if _libs.is_some() {
            let mut lib_clone = _libs.clone().unwrap();
            // finish link
            for (key, value) in _libs.unwrap().into_iter() {
                let lib_bytecode = value.deploy_bytecode_str;
                let lib_bytecode_hex = Bytes::from(hex::decode(lib_bytecode.clone()).unwrap());
                let lib_addr = compute_address(&key);
                let lib_addr = EVMAddress::from_str(lib_addr.as_str()).unwrap();
                let lib_addr =
                    evm_executor.deploy(Bytecode::new_raw(lib_bytecode_hex.clone()), None, lib_addr, &mut state);
                println!(
                    "lib_bytecode is {:?} \n, lib is {:?} \n, lib_addr: {:?} \n, lib_bytecode_hex {:?} \n",
                    lib_bytecode,
                    key,
                    lib_addr.unwrap(),
                    to_hex_string(
                        evm_executor
                            .host
                            .code
                            .get(&lib_addr.unwrap())
                            .expect("get runtime bytecode failed")
                            .bytecode()
                            .to_vec()
                            .as_slice()
                    )
                );
                assert!(lib_addr.is_some(), "failed to deploy lib");
            }
        }
        let deploy_code = Bytes::from(hex::decode(deploy_code_str).unwrap());
        let addr = evm_executor.deploy(
            Bytecode::new_raw(deploy_code),
            None,
            deployed_addr, // todo: change to foundry default address
            &mut state,
        );
        unsafe {
            IN_DEPLOY = true;
        }
        assert!(addr.is_some(), "failed to deploy contract");

        let state_after_deployment = evm_executor.host.evmstate.clone();

        // invoke setUp() and fails imeediately if setUp() reverts
        let mut calldata = [0; 4];
        set_hash("setUp()", &mut calldata);

        let (res, new_vm_state) = evm_executor.fast_call(
            &[(deployer, deployed_addr, Bytes::from_iter(calldata.iter().cloned()))],
            &state_after_deployment,
            &mut state,
        );

        if !res[0].1 {
            error!("setUp() failed: {:?}", res[0].0);
        } else {
            debug!("setUp() successful!");
        }

        // now get Foundry invariant test config by calling
        // * excludeContracts() => array of addresses
        // * excludeSenders() => array of sender
        // * targetContracts() => array of addresses
        // * targetSenders() => array of sender
        // * targetSelectors() => array of selectors
        macro_rules! abi_sig {
            ($name: expr) => {
                Bytes::from_iter(ethers::abi::short_signature($name, &[]).iter().cloned())
            };
        }

        let calls = vec![
            (deployer, deployed_addr, abi_sig!("excludeContracts")),
            (deployer, deployed_addr, abi_sig!("excludeSenders")),
            (deployer, deployed_addr, abi_sig!("targetContracts")),
            (deployer, deployed_addr, abi_sig!("targetSenders")),
            (deployer, deployed_addr, abi_sig!("targetSelectors")),
            (deployer, deployed_addr, abi_sig!("v2Pairs")),
            (deployer, deployed_addr, abi_sig!("constantPairs")),
        ];

        let (res, _) = evm_executor.fast_call(&calls, &new_vm_state, &mut state);

        unsafe {
            IN_DEPLOY = false;
            SETCODE_ONLY = false;
        }

        // (address)[]
        macro_rules! parse_nth_result_addr {
            ($nth: expr) => {{
                let (res_bys, succ) = res[$nth].clone();
                let mut addrs = vec![];
                if succ {
                    let contracts = ethers::abi::decode(
                        &[ethers::abi::ParamType::Array(Box::new(
                            ethers::abi::ParamType::Address,
                        ))],
                        &res_bys,
                    )
                    .unwrap();
                    addrs = if let ethers::abi::Token::Array(contracts) = contracts[0].clone() {
                        contracts
                            .iter()
                            .map(|x| {
                                if let ethers::abi::Token::Address(addr) = x {
                                    EVMAddress::from_slice(addr.as_bytes())
                                } else {
                                    panic!("invalid address")
                                }
                            })
                            .collect::<Vec<_>>()
                    } else {
                        panic!("invalid array")
                    };
                }
                addrs
            }};
        }

        // (address addr, bytes4[] selectors)[]
        macro_rules! parse_nth_result_selector {
            ($nth: expr) => {{
                let (res_bys, succ) = res[$nth].clone();
                let mut sigs = vec![];
                if succ {
                    let sigs_parsed = ethers::abi::decode(
                        &[ethers::abi::ParamType::Array(Box::new(
                            ethers::abi::ParamType::Tuple(vec![
                                ethers::abi::ParamType::Address,
                                ethers::abi::ParamType::Array(Box::new(ethers::abi::ParamType::FixedBytes(4))),
                            ]),
                        ))],
                        &res_bys,
                    )
                    .unwrap();

                    let sigs_parsed = if let ethers::abi::Token::Array(sigs_parsed) = sigs_parsed[0].clone() {
                        sigs_parsed
                    } else {
                        panic!("invalid array")
                    };

                    sigs_parsed.iter().for_each(|x| {
                        if let ethers::abi::Token::Tuple(tuple) = x {
                            let addr = tuple[0].clone();
                            let selectors = tuple[1].clone();
                            if let (ethers::abi::Token::Address(addr), ethers::abi::Token::Array(selectors)) =
                                (addr, selectors)
                            {
                                let addr = EVMAddress::from_slice(addr.as_bytes());
                                let selectors = selectors
                                    .iter()
                                    .map(|x| {
                                        if let ethers::abi::Token::FixedBytes(bytes) = x {
                                            bytes.clone()
                                        } else {
                                            panic!("invalid bytes")
                                        }
                                    })
                                    .collect::<Vec<_>>();
                                sigs.push((addr, selectors));
                            } else {
                                panic!("invalid tuple: {:?}", tuple)
                            }
                        } else {
                            panic!("invalid tuple")
                        }
                    });
                }
                sigs
            }};
        }

        let excluded_contracts = parse_nth_result_addr!(0);
        let excluded_senders = parse_nth_result_addr!(1);
        let target_contracts = parse_nth_result_addr!(2);
        let target_senders = parse_nth_result_addr!(3);
        let target_selectors_vec = parse_nth_result_selector!(4);
        let target_selectors = {
            let mut map = HashMap::new();
            target_selectors_vec.iter().for_each(|(addr, selectors)| {
                map.entry(*addr)
                    .or_insert_with(std::vec::Vec::new)
                    .extend(selectors.clone());
            });
            map
        };

        let v2_pairs = parse_nth_result_addr!(5);

        // (address, address, uint256)[]
        let constant_pairs = if res[6].1 {
            ConstantPairMetadata::from_return_data(&res[6].0)
        } else {
            vec![]
        };

        // get the newly deployed code by setUp()
        let code: HashMap<EVMAddress, Bytes> = evm_executor
            .host
            .code
            .into_iter()
            .map(|(k, v)| (k, Bytes::from_iter(v.bytecode().iter().cloned())))
            .collect();

        let mut onchain_middleware = None;
        {
            for middleware in evm_executor.host.middlewares.read().unwrap().clone().into_iter() {
                if middleware.borrow().get_type() == MiddlewareType::OnChain {
                    unsafe {
                        let onchain = middleware.borrow().as_any().downcast_ref_unchecked::<OnChain>().clone();
                        onchain_middleware = Some(onchain);
                    }
                }
            }
        }

        match &onchain_middleware {
            Some(onchain) => {
                evm_executor.host.env.block.number = EVMU256::from(
                    u64::from_str_radix(onchain.endpoint.block_number.trim_start_matches("0x"), 16).unwrap(),
                );
            }
            None => {}
        }

        SetupData {
            evmstate: new_vm_state,
            env: evm_executor.host.env.clone(),
            code,
            excluded_contracts,
            excluded_senders,
            target_contracts,
            target_senders,
            target_selectors,
            v2_pairs,
            constant_pairs,
            onchain_middleware,
        }
    }
}

type CombinedJsonOutput = (
    Vec<(String, String)>,
    Option<Vec<(String, String)>>,
    HashMap<String, String>,
);
// Return (vec_files, vec_replacements, vec_raw_source_map)
pub fn extract_combined_json(json: String, target_path: String, base_path: Option<String>) -> CombinedJsonOutput {
    let map_json = serde_json::from_str::<serde_json::Value>(&json).unwrap();
    let contracts = map_json["contracts"].as_object().expect("contracts not found");
    let file_list = map_json["sourceList"]
        .as_array()
        .expect("sourceList not found")
        .iter()
        .map(|x| x.as_str().expect("sourceList is not string").to_string())
        .collect::<Vec<String>>();

    // the base_path can be either absolute or relative
    // if absolute, then we use it as is
    // if relative, then we concat it with target_path
    let root_path = match base_path.clone() {
        Some(base_path) => {
            let base_pathbuf = PathBuf::from(base_path.clone());
            if !base_pathbuf.is_absolute() {
                // Remove the last "*" char and join with target_path
                PathBuf::from(format!("{}{}", target_path.clone().strip_suffix('*').unwrap(), base_path).to_string())
            } else {
                PathBuf::from(base_path)
            }
        }
        // Remove the last "*" char
        None => PathBuf::from(target_path.clone().strip_suffix('*').unwrap()),
    };

    let mut vec_filenames = Vec::<(String, String)>::new();
    for filename in &file_list {
        // construct the full path
        let mut pathbuf = root_path.clone();
        pathbuf.push(filename);
        // read the file
        let mut file = match File::open(&pathbuf) {
            Ok(file) => file,
            Err(_) => {
                let mut pathbuf = PathBuf::from(base_path.clone().unwrap_or(".".to_string()));
                pathbuf.push(filename);
                File::open(&pathbuf).unwrap_or_else(|_| panic!("cannot open file {}", pathbuf.display()))
            }
        };
        let mut buf = String::new();
        file.read_to_string(&mut buf).unwrap();
        // push to vec_filenames
        vec_filenames.push((filename.clone(), buf));
    }

    let mut raw_source_maps = HashMap::<String, String>::new();
    for (contract_name, contract_info) in contracts {
        let splitter = contract_name.split(':').collect::<Vec<&str>>();
        let contract_name = splitter.last().unwrap().to_string();

        let srcmap_runtime = contract_info["srcmap-runtime"]
            .as_str()
            .expect("srcmap-runtime not found")
            .to_string();

        raw_source_maps.insert(contract_name.clone(), srcmap_runtime);
    }

    (vec_filenames, None, raw_source_maps)
}

pub fn extract_sig_from_contract(code: &str) -> Vec<[u8; 4]> {
    let bytes = hex::decode(code).expect("failed to decode contract code");
    let mut code_sig = HashSet::new();

    let bytecode = all_bytecode(&bytes);

    for (pc, op) in bytecode {
        if op == PUSH4 {
            // ensure we have enough bytes
            if pc + 6 >= bytes.len() {
                break;
            }

            // Solidity: check whether next ops is EQ
            // Vyper: check whether next 2 ops contain XOR
            if bytes[pc + 5] == 0x14 || bytes[pc + 5] == 0x18 || bytes[pc + 6] == 0x18 || bytes[pc + 6] == 0x14 {
                let mut sig_bytes = vec![];
                for j in 0..4 {
                    sig_bytes.push(*bytes.get(pc + j + 1).unwrap());
                }
                code_sig.insert(sig_bytes.try_into().unwrap());
            }
        }
    }
    code_sig.iter().cloned().collect_vec()
}

pub fn compute_address(target_salt: &(String, String)) -> String {
    let mut hasher = Keccak256::new();
    hasher.update(target_salt.0.as_bytes());
    hasher.update(target_salt.1.as_bytes());
    let result = hasher.finalize();
    Address::from_slice(&result[12..]).to_string().to_lowercase().as_str()[2..].to_string()
}

pub fn to_hex_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| match format!("{:02x}", b) {
            s => s.to_string(),
        })
        .collect::<Vec<String>>()
        .join("")
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{evm::parse_constructor_args_string, skip_cbor, state::FuzzState};

    #[test]
    fn test_load() {
        let codes: Vec<String> = vec![];
        // let mut args: HashMap<String, Vec<String>> = HashMap::new();
        let input = "contract1:88,97C6D26d7E0D316850A967b46845E15a32666d25,1800;contract2:88,97C6D26d7E0D316850A967b46845E15a32666d25,1800".to_string();
        let args = parse_constructor_args_string(input);
        let loader = ContractLoader::from_glob(
            "tests/evm/real_balance/*",
            &mut FuzzState::new(0),
            &codes,
            &args,
            String::from(""),
            None,
        );
        debug!(
            "{:?}",
            loader.contracts.iter().map(|x| x.name.clone()).collect::<Vec<String>>()
        );
    }

    #[test]
    fn test_extract_function_hash() {
        // uniswap v2 router
        let code = "60c06040523480156200001157600080fd5b506040516200573e3803806200573e833981810160405260408110156200003757600080fd5b5080516020909101516001600160601b0319606092831b8116608052911b1660a05260805160601c60a05160601c6155b762000187600039806101ac5280610e5d5280610e985280610fd5528061129852806116f252806118d65280611e1e5280611fa252806120725280612179528061232c52806123c15280612673528061271a52806127ef52806128f452806129dc5280612a5d52806130ec5280613422528061347852806134ac528061352d528061374752806138f7528061398c5250806110c752806111c5528061136b52806113a4528061154f52806117e452806118b45280611aa1528061225f528061240052806125a95280612a9c5280612ddf5280613071528061309a52806130ca52806132a75280613456528061382d52806139cb528061444a528061448d52806147ed52806149ce5280614f49528061502a52806150aa52506155b76000f3fe60806040526004361061018f5760003560e01c80638803dbee116100d6578063c45a01551161007f578063e8e3370011610059578063e8e3370014610c71578063f305d71914610cfe578063fb3bdb4114610d51576101d5565b8063c45a015514610b25578063d06ca61f14610b3a578063ded9382a14610bf1576101d5565b8063af2979eb116100b0578063af2979eb146109c8578063b6f9de9514610a28578063baa2abde14610abb576101d5565b80638803dbee146108af578063ad5c464814610954578063ad615dec14610992576101d5565b80634a25d94a11610138578063791ac94711610112578063791ac947146107415780637ff36ab5146107e657806385f8c25914610879576101d5565b80634a25d94a146105775780635b0d59841461061c5780635c11d7951461069c576101d5565b80631f00ca74116101695780631f00ca74146103905780632195995c1461044757806338ed1739146104d2576101d5565b806302751cec146101da578063054d50d41461025357806318cbafe51461029b576101d5565b366101d5573373ffffffffffffffffffffffffffffffffffffffff7f000000000000000000000000000000000000000000000000000000000000000016146101d357fe5b005b600080fd5b3480156101e657600080fd5b5061023a600480360360c08110156101fd57600080fd5b5073ffffffffffffffffffffffffffffffffffffffff81358116916020810135916040820135916060810135916080820135169060a00135610de4565b6040805192835260208301919091528051918290030190f35b34801561025f57600080fd5b506102896004803603606081101561027657600080fd5b5080359060208101359060400135610f37565b60408051918252519081900360200190f35b3480156102a757600080fd5b50610340600480360360a08110156102be57600080fd5b8135916020810135918101906060810160408201356401000000008111156102e557600080fd5b8201836020820111156102f757600080fd5b8035906020019184602083028401116401000000008311171561031957600080fd5b919350915073ffffffffffffffffffffffffffffffffffffffff8135169060200135610f4c565b60408051602080825283518183015283519192839290830191858101910280838360005b8381101561037c578181015183820152602001610364565b505050509050019250505060405180910390f35b34801561039c57600080fd5b50610340600480360360408110156103b357600080fd5b813591908101906040810160208201356401000000008111156103d557600080fd5b8201836020820111156103e757600080fd5b8035906020019184602083028401116401000000008311171561040957600080fd5b919080806020026020016040519081016040528093929190818152602001838360200280828437600092019190915250929550611364945050505050565b34801561045357600080fd5b5061023a600480360361016081101561046b57600080fd5b5073ffffffffffffffffffffffffffffffffffffffff8135811691602081013582169160408201359160608101359160808201359160a08101359091169060c08101359060e081013515159060ff610100820135169061012081013590610140013561139a565b3480156104de57600080fd5b50610340600480360360a08110156104f557600080fd5b81359160208101359181019060608101604082013564010000000081111561051c57600080fd5b82018360208201111561052e57600080fd5b8035906020019184602083028401116401000000008311171561055057600080fd5b919350915073ffffffffffffffffffffffffffffffffffffffff81351690602001356114d8565b34801561058357600080fd5b50610340600480360360a081101561059a57600080fd5b8135916020810135918101906060810160408201356401000000008111156105c157600080fd5b8201836020820111156105d357600080fd5b803590602001918460208302840111640100000000831117156105f557600080fd5b919350915073ffffffffffffffffffffffffffffffffffffffff8135169060200135611669565b34801561062857600080fd5b50610289600480360361014081101561064057600080fd5b5073ffffffffffffffffffffffffffffffffffffffff81358116916020810135916040820135916060810135916080820135169060a08101359060c081013515159060ff60e082013516906101008101359061012001356118ac565b3480156106a857600080fd5b506101d3600480360360a08110156106bf57600080fd5b8135916020810135918101906060810160408201356401000000008111156106e657600080fd5b8201836020820111156106f857600080fd5b8035906020019184602083028401116401000000008311171561071a57600080fd5b919350915073ffffffffffffffffffffffffffffffffffffffff81351690602001356119fe565b34801561074d57600080fd5b506101d3600480360360a081101561076457600080fd5b81359160208101359181019060608101604082013564010000000081111561078b57600080fd5b82018360208201111561079d57600080fd5b803590602001918460208302840111640100000000831117156107bf57600080fd5b919350915073ffffffffffffffffffffffffffffffffffffffff8135169060200135611d97565b610340600480360360808110156107fc57600080fd5b8135919081019060408101602082013564010000000081111561081e57600080fd5b82018360208201111561083057600080fd5b8035906020019184602083028401116401000000008311171561085257600080fd5b919350915073ffffffffffffffffffffffffffffffffffffffff8135169060200135612105565b34801561088557600080fd5b506102896004803603606081101561089c57600080fd5b5080359060208101359060400135612525565b3480156108bb57600080fd5b50610340600480360360a08110156108d257600080fd5b8135916020810135918101906060810160408201356401000000008111156108f957600080fd5b82018360208201111561090b57600080fd5b8035906020019184602083028401116401000000008311171561092d57600080fd5b919350915073ffffffffffffffffffffffffffffffffffffffff8135169060200135612532565b34801561096057600080fd5b50610969612671565b6040805173ffffffffffffffffffffffffffffffffffffffff9092168252519081900360200190f35b34801561099e57600080fd5b50610289600480360360608110156109b557600080fd5b5080359060208101359060400135612695565b3480156109d457600080fd5b50610289600480360360c08110156109eb57600080fd5b5073ffffffffffffffffffffffffffffffffffffffff81358116916020810135916040820135916060810135916080820135169060a001356126a2565b6101d360048036036080811015610a3e57600080fd5b81359190810190604081016020820135640100000000811115610a6057600080fd5b820183602082011115610a7257600080fd5b80359060200191846020830284011164010000000083111715610a9457600080fd5b919350915073ffffffffffffffffffffffffffffffffffffffff8135169060200135612882565b348015610ac757600080fd5b5061023a600480360360e0811015610ade57600080fd5b5073ffffffffffffffffffffffffffffffffffffffff8135811691602081013582169160408201359160608101359160808201359160a08101359091169060c00135612d65565b348015610b3157600080fd5b5061096961306f565b348015610b4657600080fd5b5061034060048036036040811015610b5d57600080fd5b81359190810190604081016020820135640100000000811115610b7f57600080fd5b820183602082011115610b9157600080fd5b80359060200191846020830284011164010000000083111715610bb357600080fd5b919080806020026020016040519081016040528093929190818152602001838360200280828437600092019190915250929550613093945050505050565b348015610bfd57600080fd5b5061023a6004803603610140811015610c1557600080fd5b5073ffffffffffffffffffffffffffffffffffffffff81358116916020810135916040820135916060810135916080820135169060a08101359060c081013515159060ff60e082013516906101008101359061012001356130c0565b348015610c7d57600080fd5b50610ce06004803603610100811015610c9557600080fd5b5073ffffffffffffffffffffffffffffffffffffffff8135811691602081013582169160408201359160608101359160808201359160a08101359160c0820135169060e00135613218565b60408051938452602084019290925282820152519081900360600190f35b610ce0600480360360c0811015610d1457600080fd5b5073ffffffffffffffffffffffffffffffffffffffff81358116916020810135916040820135916060810135916080820135169060a001356133a7565b61034060048036036080811015610d6757600080fd5b81359190810190604081016020820135640100000000811115610d8957600080fd5b820183602082011115610d9b57600080fd5b80359060200191846020830284011164010000000083111715610dbd57600080fd5b919350915073ffffffffffffffffffffffffffffffffffffffff81351690602001356136d3565b6000808242811015610e5757604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601860248201527f556e69737761705632526f757465723a20455850495245440000000000000000604482015290519081900360640190fd5b610e86897f00000000000000000000000000000000000000000000000000000000000000008a8a8a308a612d65565b9093509150610e96898685613b22565b7f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff16632e1a7d4d836040518263ffffffff1660e01b815260040180828152602001915050600060405180830381600087803b158015610f0957600080fd5b505af1158015610f1d573d6000803e3d6000fd5b50505050610f2b8583613cff565b50965096945050505050565b6000610f44848484613e3c565b949350505050565b60608142811015610fbe57604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601860248201527f556e69737761705632526f757465723a20455850495245440000000000000000604482015290519081900360640190fd5b73ffffffffffffffffffffffffffffffffffffffff7f00000000000000000000000000000000000000000000000000000000000000001686867fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff810181811061102357fe5b9050602002013573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16146110c257604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601d60248201527f556e69737761705632526f757465723a20494e56414c49445f50415448000000604482015290519081900360640190fd5b6111207f000000000000000000000000000000000000000000000000000000000000000089888880806020026020016040519081016040528093929190818152602001838360200280828437600092019190915250613f6092505050565b9150868260018451038151811061113357fe5b60200260200101511015611192576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252602b815260200180615508602b913960400191505060405180910390fd5b611257868660008181106111a257fe5b9050602002013573ffffffffffffffffffffffffffffffffffffffff163361123d7f00000000000000000000000000000000000000000000000000000000000000008a8a60008181106111f157fe5b9050602002013573ffffffffffffffffffffffffffffffffffffffff168b8b600181811061121b57fe5b9050602002013573ffffffffffffffffffffffffffffffffffffffff166140c6565b8560008151811061124a57fe5b60200260200101516141b1565b61129682878780806020026020016040519081016040528093929190818152602001838360200280828437600092019190915250309250614381915050565b7f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff16632e1a7d4d836001855103815181106112e257fe5b60200260200101516040518263ffffffff1660e01b815260040180828152602001915050600060405180830381600087803b15801561132057600080fd5b505af1158015611334573d6000803e3d6000fd5b50505050611359848360018551038151811061134c57fe5b6020026020010151613cff565b509695505050505050565b60606113917f00000000000000000000000000000000000000000000000000000000000000008484614608565b90505b92915050565b60008060006113ca7f00000000000000000000000000000000000000000000000000000000000000008f8f6140c6565b90506000876113d9578c6113fb565b7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff5b604080517fd505accf00000000000000000000000000000000000000000000000000000000815233600482015230602482015260448101839052606481018c905260ff8a16608482015260a4810189905260c48101889052905191925073ffffffffffffffffffffffffffffffffffffffff84169163d505accf9160e48082019260009290919082900301818387803b15801561149757600080fd5b505af11580156114ab573d6000803e3d6000fd5b505050506114be8f8f8f8f8f8f8f612d65565b809450819550505050509b509b9950505050505050505050565b6060814281101561154a57604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601860248201527f556e69737761705632526f757465723a20455850495245440000000000000000604482015290519081900360640190fd5b6115a87f000000000000000000000000000000000000000000000000000000000000000089888880806020026020016040519081016040528093929190818152602001838360200280828437600092019190915250613f6092505050565b915086826001845103815181106115bb57fe5b6020026020010151101561161a576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252602b815260200180615508602b913960400191505060405180910390fd5b61162a868660008181106111a257fe5b61135982878780806020026020016040519081016040528093929190818152602001838360200280828437600092019190915250899250614381915050565b606081428110156116db57604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601860248201527f556e69737761705632526f757465723a20455850495245440000000000000000604482015290519081900360640190fd5b73ffffffffffffffffffffffffffffffffffffffff7f00000000000000000000000000000000000000000000000000000000000000001686867fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff810181811061174057fe5b9050602002013573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16146117df57604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601d60248201527f556e69737761705632526f757465723a20494e56414c49445f50415448000000604482015290519081900360640190fd5b61183d7f00000000000000000000000000000000000000000000000000000000000000008988888080602002602001604051908101604052809392919081815260200183836020028082843760009201919091525061460892505050565b9150868260008151811061184d57fe5b60200260200101511115611192576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260278152602001806154986027913960400191505060405180910390fd5b6000806118fa7f00000000000000000000000000000000000000000000000000000000000000008d7f00000000000000000000000000000000000000000000000000000000000000006140c6565b9050600086611909578b61192b565b7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff5b604080517fd505accf00000000000000000000000000000000000000000000000000000000815233600482015230602482015260448101839052606481018b905260ff8916608482015260a4810188905260c48101879052905191925073ffffffffffffffffffffffffffffffffffffffff84169163d505accf9160e48082019260009290919082900301818387803b1580156119c757600080fd5b505af11580156119db573d6000803e3d6000fd5b505050506119ed8d8d8d8d8d8d6126a2565b9d9c50505050505050505050505050565b8042811015611a6e57604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601860248201527f556e69737761705632526f757465723a20455850495245440000000000000000604482015290519081900360640190fd5b611afd85856000818110611a7e57fe5b9050602002013573ffffffffffffffffffffffffffffffffffffffff1633611af77f000000000000000000000000000000000000000000000000000000000000000089896000818110611acd57fe5b9050602002013573ffffffffffffffffffffffffffffffffffffffff168a8a600181811061121b57fe5b8a6141b1565b600085857fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8101818110611b2d57fe5b9050602002013573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166370a08231856040518263ffffffff1660e01b8152600401808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060206040518083038186803b158015611bc657600080fd5b505afa158015611bda573d6000803e3d6000fd5b505050506040513d6020811015611bf057600080fd5b50516040805160208881028281018201909352888252929350611c32929091899189918291850190849080828437600092019190915250889250614796915050565b86611d368288887fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8101818110611c6557fe5b9050602002013573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166370a08231886040518263ffffffff1660e01b8152600401808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060206040518083038186803b158015611cfe57600080fd5b505afa158015611d12573d6000803e3d6000fd5b505050506040513d6020811015611d2857600080fd5b50519063ffffffff614b2916565b1015611d8d576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252602b815260200180615508602b913960400191505060405180910390fd5b5050505050505050565b8042811015611e0757604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601860248201527f556e69737761705632526f757465723a20455850495245440000000000000000604482015290519081900360640190fd5b73ffffffffffffffffffffffffffffffffffffffff7f00000000000000000000000000000000000000000000000000000000000000001685857fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8101818110611e6c57fe5b9050602002013573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1614611f0b57604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601d60248201527f556e69737761705632526f757465723a20494e56414c49445f50415448000000604482015290519081900360640190fd5b611f1b85856000818110611a7e57fe5b611f59858580806020026020016040519081016040528093929190818152602001838360200280828437600092019190915250309250614796915050565b604080517f70a08231000000000000000000000000000000000000000000000000000000008152306004820152905160009173ffffffffffffffffffffffffffffffffffffffff7f000000000000000000000000000000000000000000000000000000000000000016916370a0823191602480820192602092909190829003018186803b158015611fe957600080fd5b505afa158015611ffd573d6000803e3d6000fd5b505050506040513d602081101561201357600080fd5b5051905086811015612070576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252602b815260200180615508602b913960400191505060405180910390fd5b7f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff16632e1a7d4d826040518263ffffffff1660e01b815260040180828152602001915050600060405180830381600087803b1580156120e357600080fd5b505af11580156120f7573d6000803e3d6000fd5b50505050611d8d8482613cff565b6060814281101561217757604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601860248201527f556e69737761705632526f757465723a20455850495245440000000000000000604482015290519081900360640190fd5b7f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff16868660008181106121bb57fe5b9050602002013573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff161461225a57604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601d60248201527f556e69737761705632526f757465723a20494e56414c49445f50415448000000604482015290519081900360640190fd5b6122b87f000000000000000000000000000000000000000000000000000000000000000034888880806020026020016040519081016040528093929190818152602001838360200280828437600092019190915250613f6092505050565b915086826001845103815181106122cb57fe5b6020026020010151101561232a576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252602b815260200180615508602b913960400191505060405180910390fd5b7f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff1663d0e30db08360008151811061237357fe5b60200260200101516040518263ffffffff1660e01b81526004016000604051808303818588803b1580156123a657600080fd5b505af11580156123ba573d6000803e3d6000fd5b50505050507f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff1663a9059cbb61242c7f000000000000000000000000000000000000000000000000000000000000000089896000818110611acd57fe5b8460008151811061243957fe5b60200260200101516040518363ffffffff1660e01b8152600401808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200182815260200192505050602060405180830381600087803b1580156124aa57600080fd5b505af11580156124be573d6000803e3d6000fd5b505050506040513d60208110156124d457600080fd5b50516124dc57fe5b61251b82878780806020026020016040519081016040528093929190818152602001838360200280828437600092019190915250899250614381915050565b5095945050505050565b6000610f44848484614b9b565b606081428110156125a457604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601860248201527f556e69737761705632526f757465723a20455850495245440000000000000000604482015290519081900360640190fd5b6126027f00000000000000000000000000000000000000000000000000000000000000008988888080602002602001604051908101604052809392919081815260200183836020028082843760009201919091525061460892505050565b9150868260008151811061261257fe5b6020026020010151111561161a576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260278152602001806154986027913960400191505060405180910390fd5b7f000000000000000000000000000000000000000000000000000000000000000081565b6000610f44848484614cbf565b6000814281101561271457604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601860248201527f556e69737761705632526f757465723a20455850495245440000000000000000604482015290519081900360640190fd5b612743887f00000000000000000000000000000000000000000000000000000000000000008989893089612d65565b604080517f70a0823100000000000000000000000000000000000000000000000000000000815230600482015290519194506127ed92508a91879173ffffffffffffffffffffffffffffffffffffffff8416916370a0823191602480820192602092909190829003018186803b1580156127bc57600080fd5b505afa1580156127d0573d6000803e3d6000fd5b505050506040513d60208110156127e657600080fd5b5051613b22565b7f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff16632e1a7d4d836040518263ffffffff1660e01b815260040180828152602001915050600060405180830381600087803b15801561286057600080fd5b505af1158015612874573d6000803e3d6000fd5b505050506113598483613cff565b80428110156128f257604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601860248201527f556e69737761705632526f757465723a20455850495245440000000000000000604482015290519081900360640190fd5b7f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff168585600081811061293657fe5b9050602002013573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16146129d557604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601d60248201527f556e69737761705632526f757465723a20494e56414c49445f50415448000000604482015290519081900360640190fd5b60003490507f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff1663d0e30db0826040518263ffffffff1660e01b81526004016000604051808303818588803b158015612a4257600080fd5b505af1158015612a56573d6000803e3d6000fd5b50505050507f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff1663a9059cbb612ac87f000000000000000000000000000000000000000000000000000000000000000089896000818110611acd57fe5b836040518363ffffffff1660e01b8152600401808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200182815260200192505050602060405180830381600087803b158015612b3257600080fd5b505af1158015612b46573d6000803e3d6000fd5b505050506040513d6020811015612b5c57600080fd5b5051612b6457fe5b600086867fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8101818110612b9457fe5b9050602002013573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166370a08231866040518263ffffffff1660e01b8152600401808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060206040518083038186803b158015612c2d57600080fd5b505afa158015612c41573d6000803e3d6000fd5b505050506040513d6020811015612c5757600080fd5b50516040805160208981028281018201909352898252929350612c999290918a918a918291850190849080828437600092019190915250899250614796915050565b87611d368289897fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8101818110612ccc57fe5b9050602002013573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166370a08231896040518263ffffffff1660e01b8152600401808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060206040518083038186803b158015611cfe57600080fd5b6000808242811015612dd857604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601860248201527f556e69737761705632526f757465723a20455850495245440000000000000000604482015290519081900360640190fd5b6000612e057f00000000000000000000000000000000000000000000000000000000000000008c8c6140c6565b604080517f23b872dd00000000000000000000000000000000000000000000000000000000815233600482015273ffffffffffffffffffffffffffffffffffffffff831660248201819052604482018d9052915192935090916323b872dd916064808201926020929091908290030181600087803b158015612e8657600080fd5b505af1158015612e9a573d6000803e3d6000fd5b505050506040513d6020811015612eb057600080fd5b5050604080517f89afcb4400000000000000000000000000000000000000000000000000000000815273ffffffffffffffffffffffffffffffffffffffff888116600483015282516000938493928616926389afcb44926024808301939282900301818787803b158015612f2357600080fd5b505af1158015612f37573d6000803e3d6000fd5b505050506040513d6040811015612f4d57600080fd5b50805160209091015190925090506000612f678e8e614d9f565b5090508073ffffffffffffffffffffffffffffffffffffffff168e73ffffffffffffffffffffffffffffffffffffffff1614612fa4578183612fa7565b82825b90975095508a871015613005576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260268152602001806154bf6026913960400191505060405180910390fd5b8986101561305e576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260268152602001806154256026913960400191505060405180910390fd5b505050505097509795505050505050565b7f000000000000000000000000000000000000000000000000000000000000000081565b60606113917f00000000000000000000000000000000000000000000000000000000000000008484613f60565b60008060006131107f00000000000000000000000000000000000000000000000000000000000000008e7f00000000000000000000000000000000000000000000000000000000000000006140c6565b905060008761311f578c613141565b7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff5b604080517fd505accf00000000000000000000000000000000000000000000000000000000815233600482015230602482015260448101839052606481018c905260ff8a16608482015260a4810189905260c48101889052905191925073ffffffffffffffffffffffffffffffffffffffff84169163d505accf9160e48082019260009290919082900301818387803b1580156131dd57600080fd5b505af11580156131f1573d6000803e3d6000fd5b505050506132038e8e8e8e8e8e610de4565b909f909e509c50505050505050505050505050565b6000806000834281101561328d57604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601860248201527f556e69737761705632526f757465723a20455850495245440000000000000000604482015290519081900360640190fd5b61329b8c8c8c8c8c8c614ef2565b909450925060006132cd7f00000000000000000000000000000000000000000000000000000000000000008e8e6140c6565b90506132db8d3383886141b1565b6132e78c3383876141b1565b8073ffffffffffffffffffffffffffffffffffffffff16636a627842886040518263ffffffff1660e01b8152600401808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001915050602060405180830381600087803b15801561336657600080fd5b505af115801561337a573d6000803e3d6000fd5b505050506040513d602081101561339057600080fd5b5051949d939c50939a509198505050505050505050565b6000806000834281101561341c57604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601860248201527f556e69737761705632526f757465723a20455850495245440000000000000000604482015290519081900360640190fd5b61344a8a7f00000000000000000000000000000000000000000000000000000000000000008b348c8c614ef2565b9094509250600061349c7f00000000000000000000000000000000000000000000000000000000000000008c7f00000000000000000000000000000000000000000000000000000000000000006140c6565b90506134aa8b3383886141b1565b7f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff1663d0e30db0856040518263ffffffff1660e01b81526004016000604051808303818588803b15801561351257600080fd5b505af1158015613526573d6000803e3d6000fd5b50505050507f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff1663a9059cbb82866040518363ffffffff1660e01b8152600401808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200182815260200192505050602060405180830381600087803b1580156135d257600080fd5b505af11580156135e6573d6000803e3d6000fd5b505050506040513d60208110156135fc57600080fd5b505161360457fe5b8073ffffffffffffffffffffffffffffffffffffffff16636a627842886040518263ffffffff1660e01b8152600401808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001915050602060405180830381600087803b15801561368357600080fd5b505af1158015613697573d6000803e3d6000fd5b505050506040513d60208110156136ad57600080fd5b50519250348410156136c5576136c533853403613cff565b505096509650969350505050565b6060814281101561374557604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601860248201527f556e69737761705632526f757465723a20455850495245440000000000000000604482015290519081900360640190fd5b7f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff168686600081811061378957fe5b9050602002013573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff161461382857604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601d60248201527f556e69737761705632526f757465723a20494e56414c49445f50415448000000604482015290519081900360640190fd5b6138867f00000000000000000000000000000000000000000000000000000000000000008888888080602002602001604051908101604052809392919081815260200183836020028082843760009201919091525061460892505050565b9150348260008151811061389657fe5b602002602001015111156138f5576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260278152602001806154986027913960400191505060405180910390fd5b7f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff1663d0e30db08360008151811061393e57fe5b60200260200101516040518263ffffffff1660e01b81526004016000604051808303818588803b15801561397157600080fd5b505af1158015613985573d6000803e3d6000fd5b50505050507f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff1663a9059cbb6139f77f000000000000000000000000000000000000000000000000000000000000000089896000818110611acd57fe5b84600081518110613a0457fe5b60200260200101516040518363ffffffff1660e01b8152600401808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200182815260200192505050602060405180830381600087803b158015613a7557600080fd5b505af1158015613a89573d6000803e3d6000fd5b505050506040513d6020811015613a9f57600080fd5b5051613aa757fe5b613ae682878780806020026020016040519081016040528093929190818152602001838360200280828437600092019190915250899250614381915050565b81600081518110613af357fe5b602002602001015134111561251b5761251b3383600081518110613b1357fe5b60200260200101513403613cff565b6040805173ffffffffffffffffffffffffffffffffffffffff8481166024830152604480830185905283518084039091018152606490920183526020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff167fa9059cbb00000000000000000000000000000000000000000000000000000000178152925182516000946060949389169392918291908083835b60208310613bf857805182527fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe09092019160209182019101613bbb565b6001836020036101000a0380198251168184511680821785525050505050509050019150506000604051808303816000865af19150503d8060008114613c5a576040519150601f19603f3d011682016040523d82523d6000602084013e613c5f565b606091505b5091509150818015613c8d575080511580613c8d5750808060200190516020811015613c8a57600080fd5b50515b613cf857604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601f60248201527f5472616e7366657248656c7065723a205452414e534645525f4641494c454400604482015290519081900360640190fd5b5050505050565b6040805160008082526020820190925273ffffffffffffffffffffffffffffffffffffffff84169083906040518082805190602001908083835b60208310613d7657805182527fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe09092019160209182019101613d39565b6001836020036101000a03801982511681845116808217855250505050505090500191505060006040518083038185875af1925050503d8060008114613dd8576040519150601f19603f3d011682016040523d82523d6000602084013e613ddd565b606091505b5050905080613e37576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260238152602001806154e56023913960400191505060405180910390fd5b505050565b6000808411613e96576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252602b815260200180615557602b913960400191505060405180910390fd5b600083118015613ea65750600082115b613efb576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252602881526020018061544b6028913960400191505060405180910390fd5b6000613f0f856103e563ffffffff6151f316565b90506000613f23828563ffffffff6151f316565b90506000613f4983613f3d886103e863ffffffff6151f316565b9063ffffffff61527916565b9050808281613f5457fe5b04979650505050505050565b6060600282511015613fd357604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601e60248201527f556e697377617056324c6962726172793a20494e56414c49445f504154480000604482015290519081900360640190fd5b815167ffffffffffffffff81118015613feb57600080fd5b50604051908082528060200260200182016040528015614015578160200160208202803683370190505b509050828160008151811061402657fe5b60200260200101818152505060005b60018351038110156140be576000806140788786858151811061405457fe5b602002602001015187866001018151811061406b57fe5b60200260200101516152eb565b9150915061409a84848151811061408b57fe5b60200260200101518383613e3c565b8484600101815181106140a957fe5b60209081029190910101525050600101614035565b509392505050565b60008060006140d58585614d9f565b604080517fffffffffffffffffffffffffffffffffffffffff000000000000000000000000606094851b811660208084019190915293851b81166034830152825160288184030181526048830184528051908501207fff0000000000000000000000000000000000000000000000000000000000000060688401529a90941b9093166069840152607d8301989098527f96e8ac4277198ff8b6f785478aa9a39f403cb768dd02cbee326c3e7da348845f609d808401919091528851808403909101815260bd909201909752805196019590952095945050505050565b6040805173ffffffffffffffffffffffffffffffffffffffff85811660248301528481166044830152606480830185905283518084039091018152608490920183526020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff167f23b872dd0000000000000000000000000000000000000000000000000000000017815292518251600094606094938a169392918291908083835b6020831061428f57805182527fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe09092019160209182019101614252565b6001836020036101000a0380198251168184511680821785525050505050509050019150506000604051808303816000865af19150503d80600081146142f1576040519150601f19603f3d011682016040523d82523d6000602084013e6142f6565b606091505b5091509150818015614324575080511580614324575080806020019051602081101561432157600080fd5b50515b614379576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260248152602001806155336024913960400191505060405180910390fd5b505050505050565b60005b60018351038110156146025760008084838151811061439f57fe5b60200260200101518584600101815181106143b657fe5b60200260200101519150915060006143ce8383614d9f565b50905060008785600101815181106143e257fe5b602002602001015190506000808373ffffffffffffffffffffffffffffffffffffffff168673ffffffffffffffffffffffffffffffffffffffff161461442a5782600061442e565b6000835b91509150600060028a510388106144455788614486565b6144867f0000000000000000000000000000000000000000000000000000000000000000878c8b6002018151811061447957fe5b60200260200101516140c6565b90506144b37f000000000000000000000000000000000000000000000000000000000000000088886140c6565b73ffffffffffffffffffffffffffffffffffffffff1663022c0d9f84848460006040519080825280601f01601f1916602001820160405280156144fd576020820181803683370190505b506040518563ffffffff1660e01b8152600401808581526020018481526020018373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200180602001828103825283818151815260200191508051906020019080838360005b83811015614588578181015183820152602001614570565b50505050905090810190601f1680156145b55780820380516001836020036101000a031916815260200191505b5095505050505050600060405180830381600087803b1580156145d757600080fd5b505af11580156145eb573d6000803e3d6000fd5b505060019099019850614384975050505050505050565b50505050565b606060028251101561467b57604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601e60248201527f556e697377617056324c6962726172793a20494e56414c49445f504154480000604482015290519081900360640190fd5b815167ffffffffffffffff8111801561469357600080fd5b506040519080825280602002602001820160405280156146bd578160200160208202803683370190505b50905082816001835103815181106146d157fe5b602090810291909101015281517fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff015b80156140be576000806147318786600186038151811061471d57fe5b602002602001015187868151811061406b57fe5b9150915061475384848151811061474457fe5b60200260200101518383614b9b565b84600185038151811061476257fe5b602090810291909101015250507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01614701565b60005b6001835103811015613e37576000808483815181106147b457fe5b60200260200101518584600101815181106147cb57fe5b60200260200101519150915060006147e38383614d9f565b50905060006148137f000000000000000000000000000000000000000000000000000000000000000085856140c6565b90506000806000808473ffffffffffffffffffffffffffffffffffffffff16630902f1ac6040518163ffffffff1660e01b815260040160606040518083038186803b15801561486157600080fd5b505afa158015614875573d6000803e3d6000fd5b505050506040513d606081101561488b57600080fd5b5080516020909101516dffffffffffffffffffffffffffff918216935016905060008073ffffffffffffffffffffffffffffffffffffffff8a8116908916146148d55782846148d8565b83835b9150915061495d828b73ffffffffffffffffffffffffffffffffffffffff166370a082318a6040518263ffffffff1660e01b8152600401808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060206040518083038186803b158015611cfe57600080fd5b955061496a868383613e3c565b9450505050506000808573ffffffffffffffffffffffffffffffffffffffff168873ffffffffffffffffffffffffffffffffffffffff16146149ae578260006149b2565b6000835b91509150600060028c51038a106149c9578a6149fd565b6149fd7f0000000000000000000000000000000000000000000000000000000000000000898e8d6002018151811061447957fe5b60408051600080825260208201928390527f022c0d9f000000000000000000000000000000000000000000000000000000008352602482018781526044830187905273ffffffffffffffffffffffffffffffffffffffff8086166064850152608060848501908152845160a48601819052969750908c169563022c0d9f958a958a958a9591949193919260c486019290918190849084905b83811015614aad578181015183820152602001614a95565b50505050905090810190601f168015614ada5780820380516001836020036101000a031916815260200191505b5095505050505050600060405180830381600087803b158015614afc57600080fd5b505af1158015614b10573d6000803e3d6000fd5b50506001909b019a506147999950505050505050505050565b8082038281111561139457604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601560248201527f64732d6d6174682d7375622d756e646572666c6f770000000000000000000000604482015290519081900360640190fd5b6000808411614bf5576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252602c8152602001806153d4602c913960400191505060405180910390fd5b600083118015614c055750600082115b614c5a576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252602881526020018061544b6028913960400191505060405180910390fd5b6000614c7e6103e8614c72868863ffffffff6151f316565b9063ffffffff6151f316565b90506000614c986103e5614c72868963ffffffff614b2916565b9050614cb56001828481614ca857fe5b049063ffffffff61527916565b9695505050505050565b6000808411614d19576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260258152602001806154736025913960400191505060405180910390fd5b600083118015614d295750600082115b614d7e576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252602881526020018061544b6028913960400191505060405180910390fd5b82614d8f858463ffffffff6151f316565b81614d9657fe5b04949350505050565b6000808273ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff161415614e27576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260258152602001806154006025913960400191505060405180910390fd5b8273ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff1610614e61578284614e64565b83835b909250905073ffffffffffffffffffffffffffffffffffffffff8216614eeb57604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601e60248201527f556e697377617056324c6962726172793a205a45524f5f414444524553530000604482015290519081900360640190fd5b9250929050565b604080517fe6a4390500000000000000000000000000000000000000000000000000000000815273ffffffffffffffffffffffffffffffffffffffff888116600483015287811660248301529151600092839283927f00000000000000000000000000000000000000000000000000000000000000009092169163e6a4390591604480820192602092909190829003018186803b158015614f9257600080fd5b505afa158015614fa6573d6000803e3d6000fd5b505050506040513d6020811015614fbc57600080fd5b505173ffffffffffffffffffffffffffffffffffffffff1614156150a257604080517fc9c6539600000000000000000000000000000000000000000000000000000000815273ffffffffffffffffffffffffffffffffffffffff8a81166004830152898116602483015291517f00000000000000000000000000000000000000000000000000000000000000009092169163c9c65396916044808201926020929091908290030181600087803b15801561507557600080fd5b505af1158015615089573d6000803e3d6000fd5b505050506040513d602081101561509f57600080fd5b50505b6000806150d07f00000000000000000000000000000000000000000000000000000000000000008b8b6152eb565b915091508160001480156150e2575080155b156150f2578793508692506151e6565b60006150ff898484614cbf565b905087811161516c5785811015615161576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260268152602001806154256026913960400191505060405180910390fd5b8894509250826151e4565b6000615179898486614cbf565b90508981111561518557fe5b878110156151de576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260268152602001806154bf6026913960400191505060405180910390fd5b94508793505b505b5050965096945050505050565b600081158061520e5750508082028282828161520b57fe5b04145b61139457604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601460248201527f64732d6d6174682d6d756c2d6f766572666c6f77000000000000000000000000604482015290519081900360640190fd5b8082018281101561139457604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601460248201527f64732d6d6174682d6164642d6f766572666c6f77000000000000000000000000604482015290519081900360640190fd5b60008060006152fa8585614d9f565b50905060008061530b8888886140c6565b73ffffffffffffffffffffffffffffffffffffffff16630902f1ac6040518163ffffffff1660e01b815260040160606040518083038186803b15801561535057600080fd5b505afa158015615364573d6000803e3d6000fd5b505050506040513d606081101561537a57600080fd5b5080516020909101516dffffffffffffffffffffffffffff918216935016905073ffffffffffffffffffffffffffffffffffffffff878116908416146153c15780826153c4565b81815b9099909850965050505050505056fe556e697377617056324c6962726172793a20494e53554646494349454e545f4f55545055545f414d4f554e54556e697377617056324c6962726172793a204944454e544943414c5f414444524553534553556e69737761705632526f757465723a20494e53554646494349454e545f425f414d4f554e54556e697377617056324c6962726172793a20494e53554646494349454e545f4c4951554944495459556e697377617056324c6962726172793a20494e53554646494349454e545f414d4f554e54556e69737761705632526f757465723a204558434553534956455f494e5055545f414d4f554e54556e69737761705632526f757465723a20494e53554646494349454e545f415f414d4f554e545472616e7366657248656c7065723a204554485f5452414e534645525f4641494c4544556e69737761705632526f757465723a20494e53554646494349454e545f4f55545055545f414d4f554e545472616e7366657248656c7065723a205452414e534645525f46524f4d5f4641494c4544556e697377617056324c6962726172793a20494e53554646494349454e545f494e5055545f414d4f554e54a26469706673582212206dd6e03c4b2c0a8e55214926227ae9e2d6f9fec2ce74a6446d615afa355c84f364736f6c634300060600330000000000000000000000005c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2";
        let sigs = skip_cbor!({ extract_sig_from_contract(code).iter().map(hex::encode).collect_vec() });
        debug!("{}: {:?}", sigs.len(), sigs);

        // counted from etherscan lol
        assert_eq!(sigs.len(), 24);
    }

    #[test]
    fn test_extract_function_hash_vyper() {
        // https://etherscan.io/address/0x847ee1227A9900B73aEeb3a47fAc92c52FD54ed9#code
        let code = "346147ac57600160015561479061001b61000039614790610000f36003361161000c57613104565b60003560e01c630b4c7e4d811861002f576064361061477e573361032052610052565b630c3e4b54811861061e576084361061477e576064358060a01c61477e57610320525b60005460021461477e57600260005561006c6103606133af565b6103605161034052346040526100836103a061333b565b6103a0805161036052602081015161038052506100a16103e06131ce565b6103e080516103a05260208101516103c052506103a051610160526103c05161018052610360516101a052610380516101c052610340516101e0526100e761040061375c565b610400516103e052601654610400526103605161042052610380516104405260006002905b8061046052610460516001811161477e5760051b60040135610480526104005161013a57610480511561477e575b610460516001811161477e5760051b6104200180516104805180820182811061477e579050905081525060010181811861010c5750506103a051610160526103c05161018052610420516101a052610440516101c052610340516101e0526101a361048061375c565b61048051610460526103e05161046051111561477e57606036610480376104005115610440576006548060011b818160011c1861477e5790508060021c90506104e05260006002905b806105005261046051610500516001811161477e5760051b610360015180820281158383830414171561477e57905090506103e051801561477e578082049050905061052052600061054052610500516001811161477e5760051b61042001516105605261056051610520511161027c57610560516105205180820382811161477e579050905061054052610297565b610520516105605180820382811161477e5790509050610540525b6104e0516105405180820281158383830414171561477e57905090506402540be40081049050610500516001811161477e5760051b6104800152610500516001811161477e576004018054610500516001811161477e5760051b610480015164012a05f20081028164012a05f20082041861477e5790506402540be4008104905080820182811061477e5790509050815550610500516001811161477e5760051b610420018051610500516001811161477e5760051b610480015180820382811161477e57905090508152506001018181186101ec5750506103a0516040526103c051606052610420516080526104405160a0526103966105406134d4565b610540805161050052602081015161052052506105005160405261052051606052610340516080526103c961056061355b565b610560516105405261040051610540516103e05180820382811161477e579050905080820281158383830414171561477e57905090506103e051801561477e57808204905090506104c05261050051610260526105205161028052610340516102a052610540516102c052610449613db056610449565b610460516104c0525b6044356104c05110156104bc5760146104e0527f536c697070616765207363726577656420796f75000000000000000000000000610500526104e0506104e0518061050001601f826000031636823750506308c379a06104a05260206104c052601f19601f6104e05101166044016104bcfd5b600435341861477e5760243515610544576003546323b872dd6104e052336105005230610520526024356105405260206104e060646104fc6000855af1610508573d600060003e3d6000fd5b3d61051f57803b1561477e57600161056052610538565b60203d1061477e576104e0518060011c61477e57610560525b6105609050511561477e575b610400516104c05180820182811061477e579050905061040052601461032051602052600052604060002080546104c05180820182811061477e5790509050815550610400516016556103205160007fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef6104c0516104e05260206104e0a3337f26f55a85081d24974e85c6c00045d0f0453991e95873f52bff0d21af4079a768604060046104e03761048051610520526104a051610540526104605161056052610400516105805260c06104e0a260206104c06003600055f35b633df02124811861063b576084361061477e57336103c05261065e565b63ddc1f59d8118610bbf5760a4361061477e576084358060a01c61477e576103c0525b60043580600f0b811861477e576103805260243580600f0b811861477e576103a05260005460021461477e57600260005561069a6104206131ce565b61042080516103e05260208101516104005250346040526106bc61046061333b565b610460805161042052602081015161044052506103e05160405261040051606052610420516080526104405160a0526106f66104a06134d4565b6104a080516104605260208101516104805250610380516001811161477e5760051b6104600151604435610380516001811161477e5760051b6103e0015180820281158383830414171561477e5790509050670de0b6b3a76400008104905080820182811061477e57905090506104a0526107726104e06133af565b6104e0516104c05261046051604052610480516060526104c05160805261079a61050061355b565b610500516104e05261038051610160526103a051610180526104a0516101a052610460516101c052610480516101e0526104c051610200526104e051610220526107e5610520613df1565b61052051610500526103a0516001811161477e5760051b61046001516105005180820382811161477e57905090506001810381811161477e579050610520526105205160065480820281158383830414171561477e57905090506402540be4008104905061054052610520516105405180820382811161477e5790509050670de0b6b3a7640000810281670de0b6b3a764000082041861477e5790506103a0516001811161477e5760051b6103e00151801561477e57808204905090506105205260643561052051101561093e57602e610560527f45786368616e676520726573756c74656420696e20666577657220636f696e73610580527f207468616e2065787065637465640000000000000000000000000000000000006105a05261056050610560518061058001601f826000031636823750506308c379a061052052602061054052601f19601f61056051011660440161053cfd5b6104a051610380516001811161477e5760051b6104600152610500516103a0516001811161477e5760051b6104600152610460516102605261048051610280526104c0516102a0526104e0516102c052610996613db0565b6105405164012a05f20081028164012a05f20082041861477e5790506402540be40081049050670de0b6b3a7640000810281670de0b6b3a764000082041861477e5790506103a0516001811161477e5760051b6103e00151801561477e5780820490509050610560526105605115610a2f576103a0516001811161477e5760040180546105605180820182811061477e57905090508155505b6003546105805261038051610ac257604435341861477e576105805163a9059cbb6105a0526103c0516105c052610520516105e05260206105a060446105bc6000855af1610a82573d600060003e3d6000fd5b3d610a9957803b1561477e57600161060052610ab2565b60203d1061477e576105a0518060011c61477e57610600525b6106009050511561477e57610b6c565b3461477e57610580516323b872dd6105a052336105c052306105e0526044356106005260206105a060646105bc6000855af1610b03573d600060003e3d6000fd5b3d610b1a57803b1561477e57600161062052610b33565b60203d1061477e576105a0518060011c61477e57610620525b6106209050511561477e5760006105a0526105a050600060006105a0516105c0610520516103c0515af1610b6c573d600060003e3d6000fd5b337f8b3e96f2b889fa771c53c981b40daf005f63f637f1869f707052d15a3dd97140610380516105a0526044356105c0526103a0516105e052610520516106005260806105a0a260206105206003600055f35b3461477e5763a461b3c88118610f1b576101c4361061477e57600435600401602081351161477e5780358060805260208201803560a052505050602435600401600a81351161477e5780358060c05260208201803560e0525050506044358060a01c61477e57610100526064358060a01c61477e57610120526084358060a01c61477e576101405260a4358060a01c61477e576101605260015461477e5732600e5573eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee610100511861477e5760006002905b8061018052670de0b6b3a7640000610180516003811161477e5760051b60c401351861477e57610180516003811161477e5760051b6101000151610180516001811161477e5760020155600101818118610c85575050610144356064810281606482041861477e579050610180526101805160095561018051600a556101643560065533600155610362601a55670de0b6b3a7640000604052670de0b6b3a7640000606052610d356101a061310a565b6101a05160195542601b5560006017610200527f43757276652e666920466163746f727920506f6f6c3a2000000000000000000061022052610200805160208201836102600181518152505080830192505050608051816102600160a051815250808201915050806102405261024090508051806101a05260208201816101c0838360045afa505050506101a05180600f55600081601f0160051c6002811161477e578015610df957905b8060051b6101c001518160100155600101818118610de0575b505050600060c051816102600160e0518152508082019150506002610200527f2d6600000000000000000000000000000000000000000000000000000000000061022052610200805160208201836102600181518152505080830192505050806102405261024090508051806012556020820180516013555050507f8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f610220526101a0516101c020610240527f0b9d98da55727756af85ff51e956250f080813d8ad137f20852fe4ea074e6420610260524661028052306102a05260a0610200526102008051602082012090506017553060007fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef6000610200526020610200a3005b63a9059cbb8118610f5f576044361061477e576004358060a01c61477e5760c0523360405260c051606052602435608052610f5461314e565b600160e052602060e0f35b6323b872dd8118611039576064361061477e576004358060a01c61477e5760c0526024358060a01c61477e5760e05260c05160405260e051606052604435608052610fa861314e565b601560c051602052600052604060002080336020526000526040600020905054610100527fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff610100511461102c576101005160443580820382811161477e5790509050601560c0516020526000526040600020803360205260005260406000209050555b6001610120526020610120f35b63095ea7b381186110b8576044361061477e576004358060a01c61477e576040526024356015336020526000526040600020806040516020526000526040600020905055604051337f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b92560243560605260206060a3600160605260206060f35b63d505accf81186113e65760e4361061477e576004358060a01c61477e576040526024358060a01c61477e576060526084358060081c61477e576080526040511561477e57606435421161477e57601860405160205260005260406000205460a0526000600260e0527f19010000000000000000000000000000000000000000000000000000000000006101005260e08051602082018361022001815181525050808301925050506017548161022001526020810190507f6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c96101405260405161016052606051610180526044356101a05260a0516101c0526064356101e05260c0610120526101208051602082012090508161022001526020810190508061020052610200905080516020820120905060c0526040513b1561132f576000604060a46101803760406101605261016080516020820183610240018281848460045afa505050808301925050506080516101c0526101c0601f81018051610200525060016101e0526101e090508051602082018361024001815181525050808301925050508061022052610220905080518060e0526020820181610100838360045afa505050507f1626ba7e00000000000000000000000000000000000000000000000000000000604051631626ba7e61016052604060c05161018052806101a052806101800160e0518082526020820181818361010060045afa5050508051806020830101601f82600003163682375050601f19601f82516020010116905081015050602061016060c461017c845afa611317573d600060003e3d6000fd5b60203d1061477e576101609050511861477e57611363565b60405160c05160e0526080516101005260a4356101205260c4356101405260206000608060e060015afa506000511861477e575b6044356015604051602052600052604060002080606051602052600052604060002090505560a0516001810181811061477e57905060186040516020526000526040600020556060516040517f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b92560443560e052602060e0a3600160e052602060e0f35b63fde625e68118611417576004361061477e576fffffffffffffffffffffffffffffffff6019541660405260206040f35b63c24c7c29811861143c576004361061477e576019548060801c905060405260206040f35b63fd0684b18118611461576004361061477e57604061145c6101606131ce565b610160f35b634903b0d1811861149b576024361061477e576020600060405261148560a061333b565b60a06004356001811161477e5760051b81019050f35b63fee3f7f981186114bd576004361061477e5764012a05f20060405260206040f35b63f446c1d081186114ec576004361061477e576114da60c06133af565b60c05160648104905060e052602060e0f35b6376a2f0f0811861150f576004361061477e57602061150b60c06133af565b60c0f35b63f2388acb8118611606576004361061477e5761152d6101806133af565b61018051610160526115406101c06131ce565b6101c080516102805260208101516102a05250600060405261156361020061333b565b61020080516102c05260208101516102e05250610280516040526102a0516060526102c0516080526102e05160a05261159d6102406134d4565b61024080516101805260208101516101a05250610180516040526101a051606052610160516080526115d06101e061355b565b6101e0516101c0526020610180516040526101a051606052610160516080526101c05160a0526116016101e06137bf565b6101e0f35b6386fc88d38118611635576004361061477e5760005460021461477e5760206116306101c0613bf2565b6101c0f35b63bb7b8b808118611745576004361061477e5760005460021461477e5761165d6101806133af565b61018051610160526116706101c06131ce565b6101c080516102805260208101516102a05250600060405261169361020061333b565b61020080516102c05260208101516102e05250610280516040526102a0516060526102c0516080526102e05160a0526116cd6102406134d4565b61024080516101805260208101516101a05250610180516040526101a051606052610160516080526117006101e061355b565b6101e0516101c0526101c051670de0b6b3a7640000810281670de0b6b3a764000082041861477e579050601654801561477e57808204905090506101e05260206101e0f35b63ed8e84f38118611940576064361061477e576044358060011c61477e57610280526117726102c06133af565b6102c0516102a052600060405261178a61030061333b565b61030080516102c05260208101516102e052506117a86103406131ce565b61034080516103005260208101516103205250610300516101605261032051610180526102c0516101a0526102e0516101c0526102a0516101e0526117ee61036061375c565b610360516103405260006002905b8061036052610360516001811161477e5760051b60040135610380526102805161184f57610360516001811161477e5760051b6102c00180516103805180820382811161477e579050905081525061187a565b610360516001811161477e5760051b6102c00180516103805180820182811061477e57905090508152505b6001018181186117fc575050610300516101605261032051610180526102c0516101a0526102e0516101c0526102a0516101e0526118b961038061375c565b6103805161036052600061038052610280516118ee57610340516103605180820382811161477e579050905061038052611909565b610360516103405180820382811161477e5790509050610380525b6103805160165480820281158383830414171561477e579050905061034051801561477e57808204905090506103a05260206103a0f35b635e0d443f8118611b60576064361061477e5760043580600f0b811861477e576103805260243580600f0b811861477e576103a0526119806104006131ce565b61040080516103c05260208101516103e052506103c0516104c0526103e0516104e05260006040526119b361044061333b565b610440805161050052602081015161052052506104c0516040526104e051606052610500516080526105205160a0526119ed6104806134d4565b61048080516104005260208101516104205250610380516001811161477e5760051b6104000151604435610380516001811161477e5760051b6103c0015180820281158383830414171561477e5790509050670de0b6b3a76400008104905080820182811061477e57905090506104405261038051610160526103a05161018052610440516101a052610400516101c052610420516101e05260403661020037611a98610480613df1565b61048051610460526103a0516001811161477e5760051b61040001516104605180820382811161477e57905090506001810381811161477e579050610480526006546104805180820281158383830414171561477e57905090506402540be400810490506104a052610480516104a05180820382811161477e5790509050670de0b6b3a7640000810281670de0b6b3a764000082041861477e5790506103a0516001811161477e5760051b6103c00151801561477e57808204905090506104c05260206104c0f35b635b36389c8118611b7c576064361061477e573360a052611b9e565b633eb1719f8118611e59576084361061477e576064358060a01c61477e5760a0525b60005460021461477e57600260005560165460c0526000604052611bc361012061333b565b610120805160e0526020810151610100525060006002905b8061012052610120516001811161477e5760051b60e0015160043580820281158383830414171561477e579050905060c051801561477e578082049050905061014052610120516001811161477e5760051b60240135610140511015611cc6576030610160527f5769746864726177616c20726573756c74656420696e20666577657220636f69610180527f6e73207468616e206578706563746564000000000000000000000000000000006101a05261016050610160518061018001601f826000031636823750506308c379a061012052602061014052601f19601f61016051011660440161013cfd5b61014051610120516001811161477e5760051b60e0015261012051611d16576000610160526101605060006000610160516101806101405160a0515af1611d8b573d600060003e3d6000fd611d8b565b60035463a9059cbb6101605260a05161018052610140516101a0526020610160604461017c6000855af1611d4f573d600060003e3d6000fd5b3d611d6657803b1561477e5760016101c052611d7f565b60203d1061477e57610160518060011c61477e576101c0525b6101c09050511561477e575b600101818118611bdb57505060c05160043580820382811161477e579050905060c0526014336020526000526040600020805460043580820382811161477e579050905081555060c0516016556000337fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef600435610120526020610120a3337f7c363854ccf79623411f8995b362bce5eddff18c927edc6f5dbbb5e05819a82c60e0516101205261010051610140526040366101603760c0516101a05260a0610120a2604060e06003600055f35b63e31032738118611e76576064361061477e573361032052611e99565b6352d2cfdd8118612464576084361061477e576064358060a01c61477e57610320525b60005460021461477e576002600055611eb36103606133af565b6103605161034052611ec66103a06131ce565b6103a0805161036052602081015161038052506000604052611ee96103e061333b565b6103e080516103a05260208101516103c05250610360516101605261038051610180526103a0516101a0526103c0516101c052610340516101e052611f2f61040061375c565b610400516103e0526103a051610400526103c0516104205260006002905b8061044052610440516001811161477e5760051b610400018051610440516001811161477e5760051b6004013580820382811161477e5790509050815250600101818118611f4d57505061036051610160526103805161018052610400516101a052610420516101c052610340516101e052611fca61046061375c565b6104605161044052604036610460376006548060011b818160011c1861477e5790508060021c90506104a05260006002905b806104c052610440516104c0516001811161477e5760051b6103a0015180820281158383830414171561477e57905090506103e051801561477e57808204905090506104e0526000610500526104c0516001811161477e5760051b610400015161052052610520516104e0511161208c57610520516104e05180820382811161477e5790509050610500526120a7565b6104e0516105205180820382811161477e5790509050610500525b6104a0516105005180820281158383830414171561477e57905090506402540be400810490506104c0516001811161477e5760051b61046001526104c0516001811161477e5760040180546104c0516001811161477e5760051b610460015164012a05f20081028164012a05f20082041861477e5790506402540be4008104905080820182811061477e57905090508155506104c0516001811161477e5760051b6104000180516104c0516001811161477e5760051b610460015180820382811161477e5790509050815250600101818118611ffc5750506103605160405261038051606052610400516080526104205160a0526121a66104c06134d4565b6104c0805161040052602081015161042052506104005160405261042051606052610340516080526121d96104e061355b565b6104e0516104c05261040051610260526104205161028052610340516102a0526104c0516102c052612209613db0565b6016546104e0526103e0516104c05180820382811161477e57905090506104e05180820281158383830414171561477e57905090506103e051801561477e57808204905090506001810181811061477e579050610500526002610500511061477e576044356105005111156122de576014610520527f536c697070616765207363726577656420796f750000000000000000000000006105405261052050610520518061054001601f826000031636823750506308c379a06104e052602061050052601f19601f6105205101166044016104fcfd5b6104e0516105005180820382811161477e57905090506104e0526104e051601655601433602052600052604060002080546105005180820382811161477e57905090508155506000337fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef61050051610520526020610520a36004351561238b57600061052052610520506000600061052051610540600435610320515af161238b573d600060003e3d6000fd5b602435156124085760035463a9059cbb610520526103205161054052602435610560526020610520604461053c6000855af16123cc573d600060003e3d6000fd5b3d6123e357803b1561477e576001610580526123fc565b60203d1061477e57610520518060011c61477e57610580525b6105809050511561477e575b337f2b5508378d7e19e0d5fa338419034731416c4f5b219a10379956f764317fd47e604060046105203761046051610560526104805161058052610440516105a0526104e0516105c05260c0610520a260206105006003600055f35b63cc2b27d781186124a9576044361061477e5760243580600f0b811861477e576104205260206004356101e05261042051610200526124a4610440614361565b610440f35b631a4d01d281186124c6576064361061477e5733610440526124e9565b63081579a58118612779576084361061477e576064358060a01c61477e57610440525b60243580600f0b811861477e576104205260005460021461477e5760026000556004356101e05261042051610200526125236104c0614361565b6104c080516104605260208101516104805260408101516104a052506044356104605110156125b25760186104c0527f4e6f7420656e6f75676820636f696e732072656d6f76656400000000000000006104e0526104c0506104c051806104e001601f826000031636823750506308c379a06104805260206104a052601f19601f6104c051011660440161049cfd5b610420516001811161477e5760040180546104805164012a05f20081028164012a05f20082041861477e5790506402540be4008104905080820182811061477e579050905081555060165460043580820382811161477e57905090506104c0526104c0516016556014336020526000526040600020805460043580820382811161477e57905090508155506000337fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef6004356104e05260206104e0a3610420516126a85760006104e0526104e050600060006104e05161050061046051610440515af161271e573d600060003e3d6000fd61271e565b60035463a9059cbb6104e0526104405161050052610460516105205260206104e060446104fc6000855af16126e2573d600060003e3d6000fd5b3d6126f957803b1561477e57600161054052612712565b60203d1061477e576104e0518060011c61477e57610540525b6105409050511561477e575b337f5ad056f2e28a8cec232015406b843668c1e36cda598127ec3b8c59b8c72773a06004356104e05261046051610500526104c0516105205260606104e0a26104a0516101c05261276d613d5b565b60206104606003600055f35b633c157e6481186128e8576044361061477e5760015463f851a44060c052602060c0600460dc845afa6127b1573d600060003e3d6000fd5b60203d1061477e5760c0518060a01c61477e5761010052610100905051331861477e57600b5462015180810181811061477e579050421061477e574262015180810181811061477e5790506024351061477e5761280e60e06133af565b60e05160c0526004356064810281606482041861477e57905060e0526004351561284057620f423f6004351115612843565b60005b1561477e5760c05160e051106128735760c051600a810281600a82041861477e57905060e0511161477e5761288f565b60c05160e051600a810281600a82041861477e5790501061477e575b60c05160095560e051600a5542600b55602435600c557fa2b71ec6df949300b59aab36b55e189697b750119dd349fcfa8c0f779e83c25460c0516101005260e051610120524261014052602435610160526080610100a1005b63551a6588811861299a576004361061477e5760015463f851a44060c052602060c0600460dc845afa612920573d600060003e3d6000fd5b60203d1061477e5760c0518060a01c61477e5761010052610100905051331861477e5761294d60e06133af565b60e05160c05260c05160095560c051600a5542600b5542600c557f46e22fb3709ad289f62ce63d469248536dbc78d82b84a3d7e74ad606dc20193860c05160e0524261010052604060e0a1005b6330c540858118612aaf576004361061477e5760015463154aa8f560605230608052602060606024607c845afa6129d6573d600060003e3d6000fd5b60203d1061477e576060518060a01c61477e5760a05260a090505160405260045460605260605115612a2a5760006080526080506000600060805160a06060516040515af1612a2a573d600060003e3d6000fd5b60055460605260605115612aa35760035463a9059cbb60805260405160a05260605160c052602060806044609c6000855af1612a6b573d600060003e3d6000fd5b3d612a8157803b1561477e57600160e052612a98565b60203d1061477e576080518060011c61477e5760e0525b60e09050511561477e575b60006004556000600555005b63a48eac9d8118612b64576024361061477e5760015463f851a440604052602060406004605c845afa612ae7573d600060003e3d6000fd5b60203d1061477e576040518060a01c61477e576080526080905051331861477e5764012a05f2006004351161477e5760085461477e57600435600755426203f480810181811061477e5790506008557f878eb36b3f197f05821c06953d9bc8f14b332a227b1e26df06a4215bbfe5d73f60043560405260206040a1005b634f12fe978118612c1d576004361061477e5760015463f851a440604052602060406004605c845afa612b9c573d600060003e3d6000fd5b60203d1061477e576040518060a01c61477e576080526080905051331861477e5760085460405260405115612bd657604051421015612bd9565b60005b1561477e5760075460605260605160065560006008557fa8715770654f54603947addf38c689adbd7182e21673b28bcf306a957aaba21560605160805260206080a1005b637f3e17cb8118612c86576024361061477e5760015463f851a440604052602060406004605c845afa612c55573d600060003e3d6000fd5b60203d1061477e576040518060a01c61477e576080526080905051331861477e576004351561477e57600435601a55005b63d1d24d498118612ce5576044361061477e576004358060201b61477e576040526024358060a01c61477e57606052600e54331861477e576060516040518060e01c90508060e01b818160e01c1861477e57905017600d556000600e55005b6354fd4d508118612d6d576004361061477e5760208060805260066040527f76362e302e31000000000000000000000000000000000000000000000000000060605260408160800181518082526020830160208301815181525050508051806020830101601f82600003163682375050601f19601f8251602001011690509050810190506080f35b63c66106578118612d98576024361061477e576004356001811161477e576002015460405260206040f35b63e2e7d2648118612dc3576024361061477e576004356001811161477e576004015460405260206040f35b63ddca3f438118612de2576004361061477e5760065460405260206040f35b6358680d0b8118612e01576004361061477e5760075460405260206040f35b63e66f43f58118612e20576004361061477e5760085460405260206040f35b635409491a8118612e3f576004361061477e5760095460405260206040f35b63b4b577ad8118612e5e576004361061477e57600a5460405260206040f35b632081066c8118612e7d576004361061477e57600b5460405260206040f35b63140522888118612e9c576004361061477e57600c5460405260206040f35b633495018d8118612ebb576004361061477e57600d5460405260206040f35b6306fdde038118612f40576004361061477e5760208060405280604001600f5480825260208201600082601f0160051c6002811161477e578015612f1257905b80601001548160051b840152600101818118612efb575b505050508051806020830101601f82600003163682375050601f19601f825160200101169050810190506040f35b6395d89b418118612f98576004361061477e576020806040528060400160125480825260208201601354815250508051806020830101601f82600003163682375050601f19601f825160200101169050810190506040f35b6370a082318118612fd3576024361061477e576004358060a01c61477e57604052601460405160205260005260406000205460605260206060f35b63dd62ed3e811861302d576044361061477e576004358060a01c61477e576040526024358060a01c61477e576060526015604051602052600052604060002080606051602052600052604060002090505460805260206080f35b6318160ddd811861304c576004361061477e5760165460405260206040f35b63313ce567811861306a576004361061477e57601260405260206040f35b633644e5158118613089576004361061477e5760175460405260206040f35b637ecebe0081186130c4576024361061477e576004358060a01c61477e57604052601860405160205260005260406000205460605260206060f35b631be913a581186130e3576004361061477e57601a5460405260206040f35b631ddc3b018118613102576004361061477e57601b5460405260206040f35b505b60006000fd5b6fffffffffffffffffffffffffffffffff6040511161477e576fffffffffffffffffffffffffffffffff6060511161477e576060518060801b905060405117815250565b60146040516020526000526040600020805460805180820382811161477e579050905081555060146060516020526000526040600020805460805180820182811061477e57905090508155506060516040517fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef60805160a052602060a0a3565b600e541561323357600a6040527f536574206f7261636c650000000000000000000000000000000000000000000060605260405060405180606001601f826000031636823750506308c379a06000526020602052601f19601f6040510116604401601cfd5b670de0b6b3a7640000604052670de0b6b3a7640000606052600d546080526080511561332b577fffffffff000000000000000000000000000000000000000000000000000000006080511661010052602060e05260e050602061014060e05161010060805173ffffffffffffffffffffffffffffffffffffffff811690508060a01c61477e575afa6132ca573d600060003e3d6000fd5b3d602081183d60201002186101205261012080518060a05260208201805160c05250505060a0511561477e5760605160c05160a05160200360031b1c80820281158383830414171561477e5790509050670de0b6b3a7640000810490506060525b6040518152606051602082015250565b4760045480820382811161477e579050905060405180820382811161477e579050905081526003546370a0823160605230608052602060606024607c845afa613389573d600060003e3d6000fd5b60203d1061477e57606090505160055480820382811161477e5790509050602082015250565b600c54604052600a5460605260405142106133d3576060518152506134d2566134d2565b600954608052600b5460a052608051606051116134625760805160805160605180820382811161477e57905090504260a05180820382811161477e579050905080820281158383830414171561477e579050905060405160a05180820382811161477e5790509050801561477e578082049050905080820382811161477e57905090508152506134d2566134d2565b60805160605160805180820382811161477e57905090504260a05180820382811161477e579050905080820281158383830414171561477e579050905060405160a05180820382811161477e5790509050801561477e578082049050905080820182811061477e57905090508152505b565b60403660c03760006002905b8061010052610100516001811161477e5760051b60400151610100516001811161477e5760051b6080015180820281158383830414171561477e5790509050670de0b6b3a764000081049050610100516001811161477e5760051b60c001526001018181186134e057505060c051815260e051602082015250565b600060a05260006002905b8060051b6040015160c05260a05160c05180820182811061477e579050905060a05260010181811861356657505060a0516135a557600081525061375a565b60a05160c0526080518060011b818160011c1861477e57905060e052600060ff905b806101005260c05160c05180820281158383830414171561477e5790509050604051801561477e578082049050905060c05180820281158383830414171561477e5790509050606051801561477e57808204905090508060021c90506101205260c0516101405260e05160a05180820281158383830414171561477e5790509050606481049050610120518060011b818160011c1861477e57905080820182811061477e579050905060c05180820281158383830414171561477e579050905060e0516064810381811161477e57905060c05180820281158383830414171561477e5790509050606481049050610120516003810281600382041861477e57905080820182811061477e5790509050801561477e578082049050905060c0526101405160c0511161371f5760016101405160c05180820382811161477e5790509050116137485760c051835250505061375a56613748565b600160c0516101405180820382811161477e5790509050116137485760c051835250505061375a565b6001018181186135c757505060006000fd5b565b61016051604052610180516060526101a0516080526101c05160a0526137836102406134d4565b6102408051610200526020810151610220525061020051604052610220516060526101e0516080526137b661024061355b565b61024051815250565b6080518060011b818160011c1861477e57905060c05260a0518060021c905060e05260006002905b806101005260e05160a05180820281158383830414171561477e5790509050610100516001811161477e5760051b60400151801561477e578082049050905060e0526001018181186137e757505060c05160405180820281158383830414171561477e579050905060648104905060e05160405180820281158383830414171561477e5790509050606051801561477e578082049050905080820182811061477e5790509050670de0b6b3a7640000810281670de0b6b3a764000082041861477e57905060c05160405180820281158383830414171561477e579050905060648104905060e05180820182811061477e5790509050801561477e5780820490509050815250565b7ffffffffffffffffffffffffffffffffffffffffffffffffdb731c958f34d94c160405113613921576000815250613bf0565b680755bf798b4a1bf1e56040511261399057600c6060527f657870206f766572666c6f77000000000000000000000000000000000000000060805260605060605180608001601f826000031636823750506308c379a06020526020604052601f19601f6060510116604401603cfd5b670de0b6b3a764000060405160601b056060526c010000000000000000000000006b8000000000000000000000006bb17217f7d1cf79abc9e3b39860605160601b0501056080526bb17217f7d1cf79abc9e3b39860805102606051036060526c10fe68e7fd37d0007b713f76506060510160a0526d02d16720577bd19bf614176fe9ea6c0100000000000000000000000060605160a05102050160a0526d04a4fd9f2a8b96949216d2255a6c60605160a051010360c0526e0587f503bb6ea29d25fcb7401964506c0100000000000000000000000060a05160c05102050160c05279d835ebba824c98fb31b83b2ca45c00000000000000000000000060605160c051020160c0526060516c240c330e9fb2d9cbaf0fd5aafc810381811361477e57905060e0526d0277594991cfc85f6e2461837cd96c0100000000000000000000000060605160e05102050160e0526d1a521255e34f6a5061b25ef1c9c46c0100000000000000000000000060605160e05102050360e0526db1bbb201f443cf962f1a1d3db4a56c0100000000000000000000000060605160e05102050160e0526e02c72388d9f74f51a9331fed693f156c0100000000000000000000000060605160e05102050360e0526e05180bb14799ab47a8a8cb2a527d576c0100000000000000000000000060605160e05102050160e05274029d9dc38563c32e5c2f6dc192ee70ef65f9978af360e05160c051056000811261477e570260c3608051037fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff811315613be15781811b613be8565b81816000031c5b905090508152505b565b601b5461010052601954610120526fffffffffffffffffffffffffffffffff6101205116671bc16d674ec80000818118671bc16d674ec8000083100218905061014052610120518060801c905061016052426101005110613c5d5761016051815250613d5956613d59565b426101005180820382811161477e5790509050670de0b6b3a7640000810281670de0b6b3a764000082041861477e579050601a54801561477e57808204905090508060ff1c61477e577f8000000000000000000000000000000000000000000000000000000000000000811461477e57600003604052613cde6101a06138ee565b6101a05161018052610140516101805180670de0b6b3a764000003670de0b6b3a7640000811161477e57905080820281158383830414171561477e5790509050610160516101805180820281158383830414171561477e579050905080820182811061477e5790509050670de0b6b3a7640000810490508152505b565b6101c05115613dae576101c05161022052613d776101e0613bf2565b6101e051610240526102205160405261024051606052613d9861020061310a565b6102005160195542601b541015613dae5742601b555b565b61026051604052610280516060526102a0516080526102c05160a052613dd76102e06137bf565b6102e05161030052610300516101c052613def613d5b565b565b61018051610160511461477e576000610180511261477e576001610180511361477e576000610160511261477e576001610160511361477e576102005161024052610220516102605261022051613e7e57613e4d6102806133af565b61028051610240526101c0516040526101e05160605261024051608052613e7561028061355b565b61028051610260525b60603661028037610260516102e052610240518060011b818160011c1861477e5790506103005260006002905b8061032052610160516103205118613eca576101a0516102a052613ef8565b610180516103205114613f5457610320516001811161477e5760051b6101c001516102a052613ef856613f54565b610280516102a05180820182811061477e5790509050610280526102e0516102605180820281158383830414171561477e57905090506102a0518060011b818160011c1861477e579050801561477e57808204905090506102e0525b600101818118613eab5750506102e0516102605180820281158383830414171561477e57905090506064810281606482041861477e579050610300518060011b818160011c1861477e579050801561477e57808204905090506102e05261028051610260516064810281606482041861477e57905061030051801561477e578082049050905080820182811061477e5790509050610320526102605161034052600060ff905b8061036052610340516102c052610340516103405180820281158383830414171561477e57905090506102e05180820182811061477e5790509050610340518060011b818160011c1861477e5790506103205180820182811061477e57905090506102605180820382811161477e5790509050801561477e5780820490509050610340526102c05161034051116140ba5760016102c0516103405180820382811161477e5790509050116140e5576103405183525050506140f7566140e5565b6001610340516102c05180820382811161477e5790509050116140e5576103405183525050506140f7565b600101818118613ffa57505060006000fd5b565b60006060511261477e5760016060511361477e5760603660e03760c051610140526040518060011b818160011c1861477e5790506101605260006002905b806101805260605161018051146141c157610180516001811161477e5760051b6080015161010052614168566141c1565b60e0516101005180820182811061477e579050905060e0526101405160c05180820281158383830414171561477e5790509050610100518060011b818160011c1861477e579050801561477e5780820490509050610140525b6001018181186141375750506101405160c05180820281158383830414171561477e57905090506064810281606482041861477e579050610160518060011b818160011c1861477e579050801561477e57808204905090506101405260e05160c0516064810281606482041861477e57905061016051801561477e578082049050905080820182811061477e57905090506101805260c0516101a052600060ff905b806101c0526101a051610120526101a0516101a05180820281158383830414171561477e57905090506101405180820182811061477e57905090506101a0518060011b818160011c1861477e5790506101805180820182811061477e579050905060c05180820382811161477e5790509050801561477e57808204905090506101a052610120516101a05111614322576001610120516101a05180820382811161477e57905090501161434d576101a051835250505061435f5661434d565b60016101a0516101205180820382811161477e57905090501161434d576101a051835250505061435f565b60010181811861426357505060006000fd5b565b61436c6102406133af565b610240516102205261437f6102806131ce565b610280805161024052602081015161026052506102405161034052610260516103605260006040526143b26102c061333b565b6102c080516103805260208101516103a052506103405160405261036051606052610380516080526103a05160a0526143ec6103006134d4565b61030080516102805260208101516102a05250610280516040526102a0516060526102205160805261441f6102e061355b565b6102e0516102c0526016546102e0526102c0516101e0516102c05180820281158383830414171561477e57905090506102e051801561477e578082049050905080820382811161477e5790509050610300526102205160405261020051606052610280516080526102a05160a0526103005160c05261449f6103406140f9565b61034051610320526006548060011b818160011c1861477e5790508060021c9050610340526040366103603760006002905b806103a05260006103c0526103a0516001811161477e5760051b61028001516103e052610200516103a05118614549576103e0516103005180820281158383830414171561477e57905090506102c051801561477e57808204905090506103205180820382811161477e57905090506103c05261458d565b6103e0516103e0516103005180820281158383830414171561477e57905090506102c051801561477e578082049050905080820382811161477e57905090506103c0525b6103e051610340516103c05180820281158383830414171561477e57905090506402540be4008104905080820382811161477e57905090506103a0516001811161477e5760051b61036001526001018181186144d1575050610200516001811161477e5760051b61036001516102205160405261020051606052610360516080526103805160a0526103005160c0526146276103c06140f9565b6103c05180820382811161477e57905090506103a052610200516001811161477e5760051b61028001516103205180820382811161477e5790509050670de0b6b3a7640000810281670de0b6b3a764000082041861477e579050610200516001811161477e5760051b6102400151801561477e57808204905090506103c0526103a0516001810381811161477e579050670de0b6b3a7640000810281670de0b6b3a764000082041861477e579050610200516001811161477e5760051b6102400151801561477e57808204905090506103a05261032051610200516001811161477e5760051b610280015260006103e052610320511561475157610280516040526102a051606052610220516080526103005160a0526147486104006137bf565b610400516103e0525b6103a05181526103c0516103a05180820382811161477e579050905060208201526103e051604082015250565b600080fda165767970657283000307000b005b600080fd";
        let sigs = extract_sig_from_contract(code).iter().map(hex::encode).collect_vec();
        debug!("{}: {:?}", sigs.len(), sigs);
        // counted from etherscan lol
        assert_eq!(sigs.len(), 56);
    }

    // #[test]
    // fn test_remote_load() {
    //     let onchain = OnChainConfig::new("https://bsc-dataseed1.binance.org/".to_string(), 56, 0);
    //
    //     let loader = ContractLoader::from_address(
    //         &onchain,
    //         vec![EVMAddress::from_str("
    // 0xa0a2ee912caf7921eaabc866c6ef6fec8f7e90a4").unwrap()],     );
    //     debug!(
    //         "{:?}",
    //         loader
    //             .contracts
    //             .iter()
    //             .map(|x| x.name.clone())
    //             .collect::<Vec<String>>()
    //     );
    // }

    #[test]
    fn test_parse_abi_not_in_json_format() {
        let abi_str = "[{'anonymous': False, 'inputs': [{'internalType': 'contract IController', 'name': '_controller', 'type': 'address'}], 'stateMutability': 'nonpayable', 'type': 'constructor'}]";
        let mut abi = ContractLoader::parse_abi_str(abi_str);
        assert_eq!(abi.len(), 1);
        let abi_cfg = abi.pop().unwrap();
        assert!(abi_cfg.is_constructor);
        assert_eq!(abi_cfg.function_name, "constructor");
        assert_eq!(abi_cfg.abi, "(address)");
    }
}
