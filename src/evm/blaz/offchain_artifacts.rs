use std::error::Error;
use bytes::Bytes;
use itertools::Itertools;
use revm_primitives::HashMap;
use serde_json::Value;
use crate::evm::blaz::{get_client, is_bytecode_similar_lax, is_bytecode_similar_strict_ranking};
use crate::evm::blaz::builder::BuildJobResult;

#[derive(Clone, Debug)]
pub struct ContractArtifact {
    pub deploy_bytecode: Bytes,
    pub abi: String,
    pub source_map: String,
    pub source_map_replacements: Vec<(String, String)>,
}

#[derive(Clone, Debug)]
pub struct OffChainArtifact {
    pub contracts: HashMap<(String, String), ContractArtifact>,
    pub sources: Vec<(String, String)>,
}

impl OffChainArtifact {
    pub fn from_json_url(url: String) -> Result<Vec<Self>, Box<dyn Error>> {
        let client = get_client();
        let resp = client.get(&url)
            .send()?;
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
            if json["success"].as_bool().expect("get status failed") != true {
                return Err("retrieve onchain job failed".into());
            }
            println!("json: {:?}", json);
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
                        let source_map_replacements = source_map_replacements.as_array().expect("get source_map_replacements failed");
                        all_source_maps_replacement.insert((filename.clone(), contract_name.clone()), source_map_replacements.iter().map(
                            |replacements| {
                                let replacements = replacements.as_array().expect("get replacements failed");
                                let source = replacements[0].as_str().expect("get source failed");
                                let target = replacements[1].as_str().expect("get target failed");
                                (source.to_string(), target.to_string())
                            }
                        ).collect_vec());
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

            let mut contracts = HashMap::new();
            for (loc, _) in &all_bytecode {
                let bytecode = all_bytecode.get(loc).expect("get bytecode failed").clone();
                let abi = all_abi.get(loc).expect("get abi failed").clone();
                let source_map = all_source_map.get(loc).expect("get source_map failed").clone();
                let source_map_replacements = all_source_maps_replacement
                    .get(loc)
                    .map(|x| x.clone())
                    .unwrap_or(vec![]);
                contracts.insert(loc.clone(), ContractArtifact {
                    deploy_bytecode: bytecode,
                    abi,
                    source_map,
                    source_map_replacements,
                });
            }
            artifacts.push(Self {
                contracts,
                sources: all_sources,
            })
        }
        Ok(artifacts)
    }

    pub fn locate(existing_artifacts: &Vec<Self>, to_find: Vec<u8>) -> Option<BuildJobResult> {
        todo!("locate artifact")
        // let mut candidates = vec![];
        // let mut all_candidates = vec![];
        // for (idx, artifact) in existing_artifacts.iter().enumerate() {
        //     for (loc, contract) in &artifact.contracts {
        //         if is_bytecode_similar_lax(to_find.clone(), contract.deploy_bytecode.to_vec()) {
        //             candidates.push((idx, loc.clone()));
        //         }
        //         all_candidates.push((idx, loc.clone()));
        //     }
        // }
        // if candidates.len() == 0 {
        //     candidates = all_candidates;
        // }
        //
        // let diffs = candidates.iter().map(|(idx, loc)| {
        //     let artifact = &existing_artifacts[*idx].contracts[loc];
        //     is_bytecode_similar_strict_ranking(to_find.clone(), artifact.deploy_bytecode.to_vec())
        // }).collect::<Vec<_>>();
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
        // let contract_artifact = &existing_artifacts[candidates[selected_idx].0].contracts[&candidates[selected_idx].1];
        // let sources = existing_artifacts[candidates[selected_idx].0].sources.clone();
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
    use super::*;

    // #[test]
    // fn test_from_url() {
    //     let url = "https://storage.googleapis.com/faas_bucket_1/client_builds/36b4bea2-2f2d-41d0-835e-db10e0a72ddf-results.json?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Credential=client-project-rw%40adept-vigil-394020.iam.gserviceaccount.com%2F20230821%2Fauto%2Fstorage%2Fgoog4_request&X-Goog-Date=20230821T163007Z&X-Goog-Expires=259200&X-Goog-SignedHeaders=host&X-Goog-Signature=89f3af8074712c7d5720844617064c1f62544c9b4667dbf7b910d988ef81c10c282ffcdd6160acff8a513e581b2516a6de8cda08f92788d210da110d87c00dff65c9a4f19fdb8e004b90578dd2978fbbf1c7bef7b9415579da7127651c46a2ae6115b1d425eba7c7950dc6df52925e7f4f204605c5c470fccebb922db95fa0d3ebeabfa33454ab1174e8ae8efa5b2cd7269c2edfd446cfee696d8b5172171eb3ae71db9da2f3554f52dc522ba01d60de71ba4fc5eb8040ff85a16fdf5685ba983f53728da90a672ada45e92eda1e4c88ee397027eacd36972f5f8551afbdf1ed747ce12e19a0c4b446e66b4cca6c8a177c2ee8e503d09930fa04ba464c1d6db6";
    //     let artifact = OffChainArtifact::from_json_url(url.to_string()).expect("get artifact failed");
    //     println!("{:?}", artifact);
    // }
}