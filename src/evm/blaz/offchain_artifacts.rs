use std::{
    collections::{BTreeMap, HashMap},
    default::Default,
    error::Error,
    process::Stdio,
};

use bytes::Bytes;
use itertools::Itertools;
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::evm::blaz::{builder::BuildJobResult, get_client};

// #[derive(Clone, Debug)]
// pub struct ContractArtifact {
//     pub deploy_bytecode: Bytes,
//     pub abi: String,
//     pub source_map: String,
//     pub source_map_replacements: Vec<(String, String)>,
// }
//
// #[derive(Clone, Debug)]
// pub struct OffChainArtifact {
//     pub contracts: HashMap<(String, String), ContractArtifact>,
//     pub sources: Vec<(String, String)>,
// }

#[derive(Clone, Default, Debug)]
pub struct ContractArtifact {
    pub deploy_bytecode_str: String,
    pub deploy_bytecode: Bytes,
    pub lib_address: BTreeMap<String, BTreeMap<String, String>>,
    pub abi: String,
    pub source_map: String,
    pub link_references: BTreeMap<String, BTreeMap<String, Vec<LinkReference>>>,
    pub source_map_replacements: Vec<(String, String)>,
}

#[derive(Clone, Debug)]
pub struct OffChainArtifact {
    pub contracts: BTreeMap<(String, String), ContractArtifact>,
    pub sources: Vec<(String, String)>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct LinkReference {
    pub(crate) start: usize,
    pub(crate) length: usize,
}

impl OffChainArtifact {
    pub fn from_json_url(url: String) -> Result<Vec<Self>, Box<dyn Error>> {
        let client = get_client();
        let resp = client.get(url).send()?;
        Self::from_json(resp.text().expect("parse json failed"))
    }

    pub fn from_file(file: String) -> Result<Vec<Self>, Box<dyn Error>> {
        let json = std::fs::read_to_string(file)?;
        Self::from_json(json)
    }

    pub fn from_json(json: String) -> Result<Vec<Self>, Box<dyn Error>> {
        let arr = serde_json::from_str::<Value>(&json)?;
        let mut artifacts = vec![];
        for json in arr.as_array().expect("failed to parse array") {
            let mut all_bytecode = HashMap::new();
            if !json["success"].as_bool().expect("get status failed") {
                return Err("retrieve onchain job failed".into());
            }
            // debug!("json: {:?}", json);
            let bytecodes = json["bytecode"].as_object().expect("get bytecode failed");
            for (filename, contract) in bytecodes {
                let contract_obj = contract.as_object().expect("get contract failed");
                for (contract_name, bytecode) in contract_obj {
                    let bytecode = bytecode.as_str().expect("get bytecode failed");
                    let bytecode = Bytes::from(hex::decode(bytecode).expect("decode bytecode failed"));
                    all_bytecode.insert((filename.clone(), contract_name.clone()), bytecode);
                }
            }

            let abis = json["abi"].as_object().expect("get abi failed");
            let mut all_abi = HashMap::new();
            for (filename, contract) in abis {
                let contract_obj = contract.as_object().expect("get contract failed");
                for (contract_name, abi) in contract_obj {
                    let abi = serde_json::to_string(abi).expect("get abi failed");
                    all_abi.insert((filename.clone(), contract_name.clone()), abi);
                }
            }

            let source_maps = json["sourcemap"].as_object().expect("get sourcemap failed");
            let mut all_source_map = HashMap::new();
            for (filename, contract) in source_maps {
                let contract_obj = contract.as_object().expect("get contract failed");
                for (contract_name, source_map) in contract_obj {
                    let source_map = source_map.as_str().expect("get source_map failed");
                    all_source_map.insert((filename.clone(), contract_name.clone()), source_map.to_string());
                }
            }

            let mut all_source_maps_replacement = HashMap::new();
            if let Some(source_maps_replacement) = json["replacements"].as_object() {
                for (filename, contract) in source_maps_replacement {
                    let contract_obj = contract.as_object().expect("get contract failed");
                    for (contract_name, source_map_replacements) in contract_obj {
                        let source_map_replacements = source_map_replacements
                            .as_array()
                            .expect("get source_map_replacements failed");
                        all_source_maps_replacement.insert(
                            (filename.clone(), contract_name.clone()),
                            source_map_replacements
                                .iter()
                                .map(|replacements| {
                                    let replacements = replacements.as_array().expect("get replacements failed");
                                    let source = replacements[0].as_str().expect("get source failed");
                                    let target = replacements[1].as_str().expect("get target failed");
                                    (source.to_string(), target.to_string())
                                })
                                .collect_vec(),
                        );
                    }
                }
            }

            let sources = json["sources"].as_object().expect("get sources failed");
            let mut all_sources = vec![(String::new(), String::new()); sources.len()];
            for (filename, source) in sources {
                let idx = source["id"].as_u64().expect("get source id failed") as usize;
                let code = source["source"].as_str().expect("get source code failed");
                all_sources[idx] = (filename.clone(), code.to_string());
            }

            let mut contracts = BTreeMap::new();
            for (loc, _) in &all_bytecode {
                let bytecode = all_bytecode.get(loc).expect("get bytecode failed").clone();
                let abi = all_abi.get(loc).expect("get abi failed").clone();
                let source_map = all_source_map.get(loc).expect("get source_map failed").clone();
                let source_map_replacements = all_source_maps_replacement.get(loc).cloned().unwrap_or(vec![]);
                contracts.insert(
                    loc.clone(),
                    ContractArtifact {
                        deploy_bytecode_str: "".to_string(),
                        deploy_bytecode: bytecode,
                        abi,
                        source_map,
                        link_references: Default::default(),
                        source_map_replacements,
                        lib_address: Default::default(),
                    },
                );
            }
            artifacts.push(Self {
                contracts,
                sources: all_sources,
            })
        }
        Ok(artifacts)
    }

    pub fn from_solc_file(file: String) -> Result<Vec<Self>, Box<dyn Error>> {
        let json = std::fs::read_to_string(file)?;
        Self::from_solc_json(json)
    }

    pub fn from_command(command: String) -> Result<Vec<Self>, Box<dyn Error>> {
        // let new_working_directory = "tests/evm_manual/story-core";
        // let new_working_directory = "tests/evm_manual/foundry1";
        // println!("Changing working directory to: {:?}", new_working_directory);
        //
        // std::env::set_current_dir(&new_working_directory)?;
        // println!("Current working directory is now: {:?}", std::env::current_dir()?);
        // println!("command is....... {:?}", command.to_string());

        // parse the command
        let mut parts = command.split_whitespace().collect_vec();
        if parts.len() < 2 {
            return Err("invalid command".into());
        }

        let bin = parts.remove(0);
        let mut folder = format!(
            ".tmp-build-info-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );
        if !std::path::Path::new(&folder).exists() {
            std::fs::create_dir_all(&folder)?;
        }

        macro_rules! remove_folder {
            () => {
                if folder.starts_with(".tmp") && std::path::Path::new(&folder).exists() {
                    std::fs::remove_dir_all(folder.clone())?;
                }
            };
        }
        let combined_json_path = folder.clone() + "/combined.json";

        match bin {
            "solc" => {
                parts.push("--combined-json=bin,bin-runtime,abi,ast,srcmap,srcmap-runtime,storage-layout");
                parts.push("--metadata");
                parts.push("--metadata-literal");
                parts.push("--overwrite");
                parts.push("-o");
                parts.push(folder.as_str());
            }
            "forge" => {
                let has_build_info = parts.iter().any(|p| p.starts_with("--build-info"));
                if !has_build_info {
                    parts.push("--build-info");
                }
                let has_build_info_path = parts.iter().any(|p| p.starts_with("--build-info-path"));
                if !has_build_info_path {
                    parts.push("--build-info-path");
                    parts.push(folder.as_str());
                } else {
                    remove_folder!();
                    return Err("build-info-path is not supported".into());
                }
            }
            "npx" | "npm" | "pnpm" | "yarn" => {
                folder = std::env::current_dir()?.to_str().unwrap().to_string() + "/artifacts/build-info";
            }
            _ => {
                remove_folder!();
                return Err(format!("unsupported command: {}", parts[0]).into());
            }
        }

        // execute the command and directly output to stdout
        let output = std::process::Command::new(bin)
            .args(parts)
            .status()
            .expect("failed to execute command");
        if !output.success() {
            remove_folder!();
            return Err(format!("command failed").into());
        }

        let res = match bin {
            "solc" => {
                let mut metadata = vec![];
                let combined_json = serde_json::from_str::<Value>(&std::fs::read_to_string(combined_json_path)?)?;
                let output = combined_json.as_object().unwrap();
                for entry in std::fs::read_dir(folder.clone())? {
                    let entry = entry?;
                    let path = entry.path();
                    if path.is_file() && path.file_name().unwrap().to_str().unwrap().ends_with("_meta.json") {
                        let json = std::fs::read_to_string(path)?;
                        metadata.push(
                            serde_json::from_str::<Value>(&json)?
                                .as_object()
                                .unwrap()
                                .get("sources")
                                .unwrap()
                                .as_object()
                                .unwrap()
                                .iter()
                                .map(|(filename, source)| {
                                    (filename.clone(), source["content"].as_str().unwrap().to_string())
                                })
                                .collect::<Vec<_>>(),
                        );
                    }
                }
                Self::_from_solc_json(
                    metadata
                        .iter()
                        .flatten()
                        .map(|(filename, source)| (filename.clone(), source.clone()))
                        .collect(),
                    &output,
                )
            }
            "forge" => {
                for entry in std::fs::read_dir(folder.clone())? {
                    let entry = entry?;
                    let path = entry.path();
                    if path.is_file() && path.file_name().unwrap().to_str().unwrap().ends_with(".json") {
                        let json = std::fs::read_to_string(path)?;
                        remove_folder!();
                        return Self::from_solc_json(json);
                    }
                }
                Err("no json file found".into())
            }
            "npx" | "npm" | "pnpm" | "yarn" => {
                for entry in std::fs::read_dir(folder.clone())? {
                    let entry = entry?;
                    let path = entry.path();
                    if path.is_file() && path.file_name().unwrap().to_str().unwrap().ends_with(".json") {
                        let json = std::fs::read_to_string(path)?;
                        return Self::from_solc_json(json);
                    }
                }
                Err("no json file found in artifacts/build-info/".into())
            }
            _ => Err("unsupported command".into()),
        };
        remove_folder!();
        res
    }

    pub fn from_solc_json(json: String) -> Result<Vec<Self>, Box<dyn Error>> {
        let arr = serde_json::from_str::<Value>(&json)?;
        let input = arr
            .as_object()
            .expect("failed to parse object")
            .get("input")
            .expect("get contracts failed")
            .as_object()
            .expect("get contracts failed");

        let output = arr
            .as_object()
            .expect("failed to parse object")
            .get("output")
            .expect("get contracts failed")
            .as_object()
            .expect("get contracts failed");

        let sources_kv = input
            .get("sources")
            .expect("get sources failed")
            .as_object()
            .expect("get sources failed");
        Self::_from_solc_json(
            sources_kv
                .iter()
                .map(|(filename, source)| {
                    (
                        filename.clone(),
                        source["content"].as_str().expect("get content failed").to_string(),
                    )
                })
                .collect(),
            output,
        )
    }

    fn _from_solc_json(
        mut input: Vec<(String, String)>,
        output: &Map<String, Value>,
    ) -> Result<Vec<Self>, Box<dyn Error>> {
        let mut result = Self {
            contracts: BTreeMap::new(),
            sources: vec![],
        };

        if let Some(errors) = output.get("errors") {
            for error in errors.as_array().expect("get errors failed") {
                let error = error.as_object().expect("get error failed");
                if error["severity"].as_str().expect("get severity failed") == "error" {
                    return Err(error["formattedMessage"]
                        .as_str()
                        .expect("get formattedMessage failed")
                        .into());
                }
            }
        }

        if let Some(srclist) = output.get("sourceList") {
            let srclist = srclist.as_array().expect("get sourceList failed");
            for filename in srclist {
                let filename = filename.as_str().expect("get filename failed");
                for (name, source) in &input {
                    if name == filename {
                        result.sources.push((name.clone(), source.clone()));
                    }
                }
            }
        } else {
            let mut insertion_order = HashMap::new();
            let mut input_idx = 0;
            for (name, _) in &input {
                let real_idx = output
                    .get("sources")
                    .expect("get sources failed")
                    .as_object()
                    .expect("failed to convert to dict")
                    .get(name)
                    .expect("failed to get file in output")
                    .get("id")
                    .expect("failed to get id")
                    .as_u64()
                    .expect("failed to convert id to u64");

                insertion_order.insert(real_idx, (input_idx, name.clone()));
                input_idx += 1;
            }

            // insert source by real_idx order
            for (_, (input_idx, name)) in insertion_order.iter().sorted() {
                let source = std::mem::take(&mut input[*input_idx]);
                result.sources.push(source);
            }

            // for (name, source) in &input {
            //     result.sources.push((name.clone(), source.clone()));
            // }
        }

        let contracts = output
            .get("contracts")
            .expect("get contracts failed")
            .as_object()
            .expect("get contracts failed");

        for (file_name, contract) in contracts {
            if file_name.contains(":") {
                let parts = file_name.split(":").collect_vec();
                let contract_name = parts[1];
                let file_name = parts[0];
                let contract = contract.as_object().expect("get contract failed");
                let bytecode = contract["bin"].as_str().expect("get bytecode failed");
                // let bytecode = Bytes::from(hex::decode(bytecode).expect("decode bytecode
                // failed"));
                let abi = serde_json::to_string(&contract["abi"]).expect("get abi failed");
                let source_map = contract["srcmap-runtime"]
                    .as_str()
                    .expect("get sourceMap failed")
                    .to_string();
                result.contracts.insert(
                    (file_name.to_string(), contract_name.to_string()),
                    ContractArtifact {
                        deploy_bytecode_str: bytecode.to_string(),
                        deploy_bytecode: Default::default(),
                        abi,
                        source_map,
                        link_references: Default::default(),
                        source_map_replacements: vec![],
                        lib_address: Default::default(),
                    },
                );
            } else {
                // 1. judge lib contract
                for (contract_name, contract) in contract.as_object().expect("get contract failed") {
                    let contract = contract.as_object().expect("get contract failed");
                    let bytecode = contract["evm"]["bytecode"]["object"]
                        .as_str()
                        .expect("get bytecode failed");
                    // let bytecode = Bytes::from(hex::decode(bytecode).expect("decode bytecode
                    // failed"));
                    let abi = serde_json::to_string(&contract["abi"]).expect("get abi failed");
                    let link_references = serde_json::from_value(contract["evm"]["bytecode"]["linkReferences"].clone())
                        .unwrap_or_default();
                    let source_map = contract["evm"]["deployedBytecode"]["sourceMap"]
                        .as_str()
                        .expect("get sourceMap failed")
                        .to_string();
                    result.contracts.insert(
                        (file_name.clone(), contract_name.clone()),
                        ContractArtifact {
                            deploy_bytecode_str: bytecode.to_string(),
                            deploy_bytecode: Bytes::default(),
                            abi,
                            source_map,
                            link_references,
                            source_map_replacements: vec![],
                            lib_address: BTreeMap::default(),
                        },
                    );
                }
            }
        }
        Ok(vec![result])
    }

    pub fn locate(_existing_artifacts: &[Self], _to_find: Vec<u8>) -> Option<BuildJobResult> {
        todo!("locate artifact")
        // let mut candidates = vec![];
        // let mut all_candidates = vec![];
        // for (idx, artifact) in existing_artifacts.iter().enumerate() {
        //     for (loc, contract) in &artifact.contracts {
        //         if is_bytecode_similar_lax(to_find.clone(),
        // contract.deploy_bytecode.to_vec()) {
        // candidates.push((idx, loc.clone()));         }
        //         all_candidates.push((idx, loc.clone()));
        //     }
        // }
        // if candidates.len() == 0 {
        //     candidates = all_candidates;
        // }
        //
        // let diffs = candidates.iter().map(|(idx, loc)| {
        //     let artifact = &existing_artifacts[*idx].contracts[loc];
        //     is_bytecode_similar_strict_ranking(to_find.clone(),
        // artifact.deploy_bytecode.to_vec()) }).collect::<Vec<_>>();
        //
        // let mut min_diff = usize::MAX;
        // let mut selected_idx = 0;
        //
        // for (idx, diff) in diffs.iter().enumerate() {
        //     if *diff < min_diff {
        //         min_diff = *diff;
        //         selected_idx = idx;
        //     }
        // }
        //
        // let contract_artifact =
        // &existing_artifacts[candidates[selected_idx].0].contracts[&
        // candidates[selected_idx].1]; let sources =
        // existing_artifacts[candidates[selected_idx].0].sources.clone();
        //
        // Some(BuildJobResult::new(
        //     sources,
        //     contract_artifact.source_map.clone(),
        //     contract_artifact.deploy_bytecode.clone(),
        //     contract_artifact.abi.clone(),
        // ))
    }
}

#[cfg(test)]
mod tests {
    // use tracing::debug;
    // use crate::evm::blaz::offchain_artifacts::OffChainArtifact;
    //
    // #[test]
    // fn test_from_url() {
    //     use super::*;
    //     // let url =
    // "/Users/shou/coding/test_foundry/build-info/
    // 685c8631ec48f140bc646da3dcfdb3d9.json";     // let artifact =
    // OffChainArtifact::from_solc_file(url.to_string()).expect("get artifact
    // failed");     // chdir
    //     let dir = "/Users/shou/coding/test_foundry";
    //     std::env::set_current_dir(dir).expect("set current dir failed");
    //
    //     let artifact = OffChainArtifact::from_command("solc
    // src/Counter.sol".to_string()).expect("get artifact failed");
    //     println!("{:?}", artifact);
    // }
}
