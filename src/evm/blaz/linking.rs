use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    error::Error,
    fs,
    io::Read,
    str::FromStr,
};

use alloy_primitives::{Address, Keccak256, B256};
use bytes::Bytes;
use itertools::Itertools;
use serde::Deserialize;
use serde_json::{Map, Value};
use tracing::debug;

use crate::evm::{
    blaz::offchain_artifacts::{ContractArtifact, OffChainArtifact},
    contract_utils::compute_address,
};

#[derive(Debug)]
pub enum LinkerError {
    MissingTargetArtifact,
    InvalidAddress,
    MissingLibraryArtifact { file: String, name: String },
}

pub struct Linker {
    pub contracts: BTreeMap<(String, String), ContractArtifact>,
}

impl Linker {
    pub fn compute_address(target_salt: &(String, String)) -> String {
        let mut hasher = Keccak256::new();
        hasher.update(target_salt.0.as_bytes());
        hasher.update(target_salt.1.as_bytes());
        let result = hasher.finalize();
        Address::from_slice(&result[12..]).to_string().to_lowercase().as_str()[2..].to_string()
    }

    pub fn link_all_contract(
        offchain_artifacts: &Vec<OffChainArtifact>,
        libs: BTreeMap<(String, String), ContractArtifact>,
    ) -> Vec<OffChainArtifact> {
        let mut offchain_artifacts_clone = offchain_artifacts.clone();
        if !libs.is_empty() {
            for (index, offchain_art) in offchain_artifacts.iter().enumerate() {
                for (contract_key, contract) in &offchain_art.contracts {
                    if !contract.link_references.is_empty() {
                        let bytecode_str =
                            Self::link_setup_target_with_compute_address(&libs.clone(), contract.clone())
                                .unwrap()
                                .deploy_bytecode_str;
                        offchain_artifacts_clone[index]
                            .contracts
                            .get_mut(contract_key)
                            .unwrap()
                            .deploy_bytecode = Bytes::from(hex::decode(bytecode_str).unwrap());
                    } else {
                        offchain_artifacts_clone[index]
                            .contracts
                            .get_mut(contract_key)
                            .unwrap()
                            .deploy_bytecode = Bytes::from(hex::decode(contract.clone().deploy_bytecode_str).unwrap());
                    }
                }
            }
        } else {
            for (index, offchain_art) in offchain_artifacts.iter().enumerate() {
                for (contract_key, contract) in &offchain_art.contracts {
                    offchain_artifacts_clone[index]
                        .contracts
                        .get_mut(contract_key)
                        .unwrap()
                        .deploy_bytecode = Bytes::from(hex::decode(contract.clone().deploy_bytecode_str).unwrap());
                }
            }
        }
        offchain_artifacts_clone
    }

    pub fn link_setup_target_with_compute_address(
        libraries: &BTreeMap<(String, String), ContractArtifact>,
        _target: ContractArtifact,
    ) -> Result<ContractArtifact, LinkerError> {
        let mut setup_contract = _target.clone();
        let mut bytecode_str = setup_contract.deploy_bytecode_str.clone();

        for ((file_name, contract_name), _) in libraries {
            let address = compute_address(&(file_name.clone(), contract_name.clone()));
            if let Some(references) = setup_contract.link_references.get(file_name) {
                if let Some(lib_references) = references.get(contract_name) {
                    for reference in lib_references {
                        let start = reference.start;
                        let length = reference.length;
                        let placeholder = &bytecode_str[start * 2..start * 2 + length * 2];
                        bytecode_str = bytecode_str.replace(placeholder, address.clone().as_str());
                    }
                }
            }
        }
        setup_contract.deploy_bytecode_str = bytecode_str;
        Ok(setup_contract)
    }

    pub fn find_all_libs_in_offchain_artifacts(
        offchain_artifacts: &Vec<OffChainArtifact>,
    ) -> Result<BTreeMap<(String, String), ContractArtifact>, Box<dyn Error>> {
        let mut all_libs = BTreeMap::new();
        for artifact in offchain_artifacts {
            let artifact = artifact.clone();
            let linker = Linker {
                contracts: artifact.contracts,
            };
            for target_id in linker.contracts.keys() {
                let mut deps = BTreeSet::new();
                if let Err(e) = linker.collect_dependencies(target_id, &mut deps) {
                    debug!("Error collecting dependencies for {:?}: {:?}", target_id, e);
                } else {
                    deps.into_iter().for_each(|id| {
                        if let Some(artifact) = linker.find_artifact_by_library_path(id) {
                            all_libs.insert(id.clone(), artifact);
                        }
                    });
                }
            }
        }
        Ok(all_libs)
    }
    /// find all libs key
    pub fn find_all_libs_key(file_path: String) -> Result<BTreeSet<(String, String)>, Box<dyn Error>> {
        let json_data = fs::read_to_string(file_path).expect("Unable to read file");
        let mut all_libs_vec = BTreeSet::new();
        let mut artifacts = Linker::from_solc_json(json_data).expect("Failed to parse JSON");

        for artifact in artifacts {
            let linker = Linker {
                contracts: artifact.contracts,
            };
            for target_id in linker.contracts.keys() {
                let mut deps = BTreeSet::new();
                if let Err(e) = linker.collect_dependencies(target_id, &mut deps) {
                    debug!("Error collecting dependencies for {:?}: {:?}", target_id, e);
                } else {
                    if !deps.is_empty() {
                        let deps: Vec<_> = deps.into_iter().map(|id| id.clone()).collect();
                        all_libs_vec.extend(deps);
                    }
                }
            }
        }
        Ok(all_libs_vec)
    }

    /// link lib inner link
    pub fn link_libs_inner_lib(
        _libs: Option<BTreeMap<(String, String), ContractArtifact>>,
    ) -> Option<BTreeMap<(String, String), ContractArtifact>> {
        if _libs.is_some() {
            let mut libs_clone = _libs.clone().unwrap();

            for (lib_key, lib_value) in _libs.unwrap().into_iter() {
                libs_clone
                    .get_mut(&lib_key)
                    .unwrap()
                    .lib_address
                    .entry(lib_key.clone().0)
                    .or_insert_with(BTreeMap::new)
                    .insert(lib_key.clone().1, compute_address(&lib_key));
            }

            let mut ret = BTreeMap::new();
            for (lib_key, lib_value) in libs_clone {
                let mut lib_value_clone = lib_value.clone();
                let mut bytecode_str = lib_value_clone.deploy_bytecode_str.clone();

                if !lib_value.clone().link_references.is_empty() {
                    for (file_name, inner_map) in lib_value.link_references {
                        for (contract_name, link_vec) in inner_map {
                            let address = compute_address(&(file_name.clone(), contract_name));

                            for reference in link_vec {
                                let start = reference.start;
                                let length = reference.length;
                                let placeholder = &bytecode_str[start * 2..start * 2 + length * 2];
                                bytecode_str = bytecode_str.replace(placeholder, address.as_str());
                            }
                        }
                    }
                }
                lib_value_clone.deploy_bytecode_str = bytecode_str;
                ret.entry(lib_key).or_insert_with(|| lib_value_clone);
            }
            Some(ret)
        } else {
            return None;
        }
    }

    pub fn collect_dependencies<'a>(
        &'a self,
        target: &(String, String),
        deps: &mut BTreeSet<&'a (String, String)>,
    ) -> Result<(), LinkerError> {
        let contract = self
            .contracts
            .get(target)
            .ok_or_else(|| LinkerError::MissingTargetArtifact)?;

        let mut references = BTreeMap::new();
        references.extend(contract.link_references.clone());

        for (file, libs) in &references {
            for contract in libs.keys() {
                let id = self.find_artifact_id_by_library_path(file, contract).ok_or_else(|| {
                    LinkerError::MissingLibraryArtifact {
                        file: file.to_string(),
                        name: contract.to_string(),
                    }
                })?;
                if deps.insert(id) {
                    self.collect_dependencies(id, deps)?;
                }
            }
        }
        Ok(())
    }

    pub fn find_artifact_by_library_path(&self, id: &(String, String)) -> Option<ContractArtifact> {
        self.contracts
            .iter()
            .find(|library| library.0 == id)
            .map(|(_, artifact)| artifact.clone())
    }

    fn find_artifact_id_by_library_path(&self, file: &str, name: &str) -> Option<&(String, String)> {
        self.contracts.keys().find(|&&(ref f, ref n)| f == file && n == name)
    }

    pub fn from_solc_json(json: String) -> Result<Vec<OffChainArtifact>, Box<dyn Error>> {
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
        input: Vec<(String, String)>,
        output: &Map<String, Value>,
    ) -> Result<Vec<OffChainArtifact>, Box<dyn Error>> {
        let mut result = OffChainArtifact {
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
            for (name, source) in &input {
                result.sources.push((name.clone(), source.clone()));
            }
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
                        lib_address: Default::default(),
                        abi,
                        source_map,
                        link_references: Default::default(),
                        source_map_replacements: vec![],
                    },
                );
            } else {
                for (contract_name, contract) in contract.as_object().expect("get contract failed") {
                    let contract = contract.as_object().expect("get contract failed");
                    let bytecode = contract["evm"]["bytecode"]["object"]
                        .as_str()
                        .expect("get bytecode failed");
                    // let bytecode = Bytes::from(hex::decode(bytecode).expect("decode bytecode
                    // failed"));
                    let link_references = serde_json::from_value(contract["evm"]["bytecode"]["linkReferences"].clone())
                        .unwrap_or_default();
                    let abi = serde_json::to_string(&contract["abi"]).expect("get abi failed");
                    let source_map = contract["evm"]["deployedBytecode"]["sourceMap"]
                        .as_str()
                        .expect("get sourceMap failed")
                        .to_string();
                    result.contracts.insert(
                        (file_name.clone(), contract_name.clone()),
                        ContractArtifact {
                            deploy_bytecode_str: bytecode.to_string(),
                            deploy_bytecode: Default::default(),
                            lib_address: Default::default(),
                            abi,
                            source_map,
                            link_references,
                            source_map_replacements: vec![],
                        },
                    );
                }
            }
        }
        Ok(vec![result])
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    // #[test]
    fn test_collect_dependencies() {
        let file_path = "tests/evm_manual/foundry1/.tmp-build-info-1716733433/f4e9a81f9387b1c60225de923fc6cdf9.json";
        let json_data = fs::read_to_string(file_path).expect("Unable to read file");
        let artifacts = Linker::from_solc_json(json_data).expect("Failed to parse JSON");

        for artifact in artifacts {
            let linker = Linker {
                contracts: artifact.contracts,
            };

            for target_id in linker.contracts.keys() {
                let mut deps = BTreeSet::new();
                if let Err(e) = linker.collect_dependencies(target_id, &mut deps) {
                    println!("Error collecting dependencies for {:?}: {:?}", target_id, e);
                } else {
                    if !deps.is_empty() {
                        println!("Dependencies for {:?}: dep is {:?}", target_id, deps);
                    }
                }
            }
        }
    }

    // #[test]
    fn test_find_libs() {
        let file_path = "tests/evm_manual/foundry1/.tmp-build-info-1716733433/f4e9a81f9387b1c60225de923fc6cdf9.json";
        let all_libs = Linker::find_all_libs_key(file_path.to_string()).unwrap();
        for lib in all_libs.into_iter() {
            println!("{:?}", lib);
        }
    }

    // #[test]
    fn test_link_libs_inner_lib() {
        let file_path = "tests/evm_manual/foundry1/.tmp-build-info-1716733433/f4e9a81f9387b1c60225de923fc6cdf9.json";
        let json_data = fs::read_to_string(file_path).expect("Unable to read file");
        let artifacts = Linker::from_solc_json(json_data).expect("Failed to parse JSON");

        let all_libs = Linker::find_all_libs_in_offchain_artifacts(&artifacts).unwrap();
        let tt = Linker::link_libs_inner_lib(Some(all_libs));
    }

    // #[test]
    fn test_link_setup_target_with_compute_address() {
        let file_path = "tests/evm_manual/foundry1/.tmp-build-info-1716733433/f4e9a81f9387b1c60225de923fc6cdf9.json";
        let json_data = fs::read_to_string(file_path).expect("Unable to read file");
        let artifacts = Linker::from_solc_json(json_data).expect("Failed to parse JSON");

        let all_libs = Linker::find_all_libs_in_offchain_artifacts(&artifacts).unwrap();
        let tt = Linker::link_libs_inner_lib(Some(all_libs)).unwrap();
    }
}
