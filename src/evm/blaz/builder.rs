use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::process::id;
use std::rc::Rc;
use std::str::FromStr;
use std::thread::sleep;
use std::time::Duration;
use bytes::Bytes;
use itertools::Itertools;
use libafl::impl_serdeany;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use crate::evm::blaz::get_client;
use crate::evm::host::FuzzHost;
use crate::evm::input::{ConciseEVMInput, EVMInput};
use crate::evm::onchain::endpoints::Chain;
use crate::evm::srcmap::parser::{decode_instructions, decode_instructions_with_replacement, SourceMapLocation};
use crate::evm::types::{EVMAddress, EVMFuzzState, ProjectSourceMapTy};
use crate::evm::vm::{EVMExecutor, EVMState};
use crate::generic_vm::vm_executor::GenericVM;

#[derive(Clone)]
pub struct BuildJob {
    pub build_server: String,
    pub replacements: HashMap<EVMAddress, Option<BuildJobResult>>
}

pub static mut BUILD_SERVER: &str = "https://solc-builder.fuzz.land/";
const NEEDS: &str = "runtimeBytecode,abi,sourcemap,sources";

impl BuildJob {
    pub fn new(build_server: String, replacements: HashMap<EVMAddress, Option<BuildJobResult>>) -> Self {
        Self {
            build_server,
            replacements
        }
    }

    pub fn async_submit_onchain_job(&self, chain: String, addr: EVMAddress) -> Option<JobContext> {
        let client = get_client();
        let url = format!("{}onchain/{}/{:?}?needs={}", self.build_server, chain, addr, NEEDS);
        println!("Submitting artifact build job to {}", url);
        let resp = client.get(&url)
            .send()
            .expect("submit onchain job failed");

        let json = serde_json::from_str::<Value>(&resp.text().expect("parse json failed")).expect("parse json failed");
        if json["code"].as_u64().expect("get status failed") != 200 {
            println!("submit onchain job failed for {:?}", addr);
            return None;
        }
        Some(JobContext::new(json["task_id"].as_str().expect("get job id failed").to_string()))
    }

    pub fn onchain_job(&self, chain: String, addr: EVMAddress) -> Option<BuildJobResult> {
        if let Some(replacement) = self.replacements.get(&addr) {
            return replacement.clone();
        }

        let job = self.async_submit_onchain_job(chain, addr);
        if job.is_none() {
            return None;
        }
        let job = job.unwrap();
        let result = job.wait_build_job();
        if result.is_none() {
            return None;
        }
        return result;
    }
}


pub struct JobContext {
    id: String,
}

impl JobContext {
    pub fn new(id: String) -> Self {
        Self { id }
    }

    pub fn wait_build_job(&self) -> Option<BuildJobResult> {
        let client = get_client();
        let url = format!("{}task/{}/", unsafe { BUILD_SERVER }, self.id);
        loop {
            println!("Retrieving artifact build job from {}", url);
            let resp = client.get(&url)
                .send()
                .expect("retrieve onchain job failed");
            let json = serde_json::from_str::<Value>(&resp.text().expect("parse json failed")).expect("parse json failed");
            if json["code"].as_u64().expect("get status failed") != 200 {
                println!("retrieve onchain job failed for {:?}", self.id);
                return None;
            }
            let status = json["status"].as_str().expect("get status failed");
            if status == "error" {
                println!("retrieve onchain job failed for {:?} due to error", self.id);
                return None;
            }

            if status != "done" {
                sleep(Duration::from_millis(500));
                continue;
            }

            let results = json["results"].as_str().expect("get results failed");
            return BuildJobResult::from_json_url(results.to_string());
        }
    }
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildJobResult {
    /// (file name, source code)
    pub sources: Vec<(String, String)>,
    pub source_maps: String,
    pub bytecodes: Bytes,
    pub abi: String,
    pub source_maps_replacements: Vec<(String, String)>,

    _cache_src_map: HashMap<usize, SourceMapLocation>,
    _cached: bool
}

impl BuildJobResult {
    pub fn new(
        sources: Vec<(String, String)>,
        source_maps: String,
        bytecodes: Bytes,
        abi: String,
        replacements: Vec<(String, String)>
    ) -> Self {
        Self {
            sources,
            source_maps,
            bytecodes,
            abi,
            source_maps_replacements: replacements,
            _cache_src_map: Default::default(),
            _cached: false,
        }
    }

    pub fn from_json_url(url: String) -> Option<Self> {
        let client = get_client();
        let resp = client.get(&url)
            .send()
            .expect("retrieve onchain job failed");

        let json = serde_json::from_str::<Value>(&resp.text().expect("parse json failed")).expect("parse json failed");
        if json["success"].as_bool().expect("get status failed") != true {
            println!("retrieve onchain job failed for {:?}", url);
            return None;
        }
        Self::from_json(&json)
    }

    pub fn from_json(json: &Value) -> Option<Self> {
        let sourcemap = json["sourcemap"].as_str().expect("get sourcemap failed");
        let mut sourcemap_replacements = vec![];
        if let Some(_replaces) = json["replaces"].as_array() {
            sourcemap_replacements = _replaces.iter().map(
                |v| {
                    let v = v.as_array().expect("get replace failed");
                    let source = v[0].as_str().expect("get source failed");
                    let target = v[1].as_str().expect("get target failed");
                    (source.to_string(), target.to_string())
                }
            ).collect_vec();
        }
        let bytecode = json["runtime_bytecode"].as_str().expect("get bytecode failed");
        let source_objs = json["sources"].as_object().expect("get sources failed");
        let mut sources = vec![(String::new(), String::new()); source_objs.len()];
        for (k, v) in source_objs {
            let idx = v["id"].as_u64().expect("get source id failed") as usize;
            let code = v["source"].as_str().expect("get source code failed");
            sources[idx] = (k.clone(), code.to_string());
        }

        let abi = serde_json::to_string(&json["abi"]).expect("get abi failed");

        Some(Self {
            sources,
            source_maps: sourcemap.to_string(),
            bytecodes: Bytes::from(hex::decode(bytecode).expect("decode bytecode failed")),
            abi: abi.to_string(),
            source_maps_replacements: sourcemap_replacements,
            _cache_src_map: Default::default(),
            _cached: false,
        })
    }

    pub fn from_multi_file(file_path: String) -> HashMap<EVMAddress, Option<Self>> {
        let content = fs::read_to_string(file_path).expect("read file failed");
        let json = serde_json::from_str::<Value>(&content).expect("parse json failed");
        let json_arr = json.as_object().expect("get json array failed");
        let mut results = HashMap::new();
        for (k, v) in json_arr {
            let result = Self::from_json(v);
            let addr = EVMAddress::from_str(k).expect("parse address failed");
            results.insert(addr, result);
        }
        results
    }


    pub fn get_sourcemap(&mut self, bytecode: Vec<u8>) -> HashMap<usize, SourceMapLocation> {
        if self._cached {
            return self._cache_src_map.clone();
        } else {
            let result = decode_instructions_with_replacement(
                bytecode,
                &self.source_maps_replacements,
                self.source_maps.clone(),
                &self.sources.iter().map(|(name, _)| (name)).cloned().collect()
            );
            self._cache_src_map = result.clone();
            self._cached = true;
            return result;
        }
    }

    pub fn get_sourcemap_executor<VS, Addr, Code, By, Loc, SlotTy, Out, I, S: 'static, CI>(
        _self: Option<&mut Self>,
        executor: &mut  Rc<RefCell<dyn GenericVM<VS, Code, By, Loc, Addr, SlotTy, Out, I, S, CI>>>,
        addr: &EVMAddress,
        additional_sourcemap: &ProjectSourceMapTy,
        pc: usize,
    ) -> Option<SourceMapLocation> {
        if let Some(_self) = _self {
            if _self._cached {
                return _self._cache_src_map.get(&pc).cloned();
            }

            let bytecode = Vec::from((**executor)
                .borrow_mut()
                .as_any()
                .downcast_ref::<EVMExecutor<EVMInput, EVMFuzzState, EVMState, ConciseEVMInput>>()
                .unwrap()
                .host
                .code
                .get(addr)
                .unwrap()
                .clone()
                .bytecode());
            return _self.get_sourcemap(bytecode).get(&pc).cloned();
        }

        if let Some(Some(srcmap)) = additional_sourcemap.get(addr) {
            return srcmap.get(&pc).cloned();
        }
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactInfoMetadata {
    pub info: HashMap<EVMAddress, BuildJobResult>
}

impl ArtifactInfoMetadata {
    pub fn new() -> Self {
        Self {
            info: HashMap::new(),
        }
    }

    pub fn add(&mut self, addr: EVMAddress, result: BuildJobResult) {
        self.info.insert(addr, result);
    }

    pub fn get(&self, addr: &EVMAddress) -> Option<&BuildJobResult> {
        self.info.get(addr)
    }

    pub fn get_mut(&mut self, addr: &EVMAddress) -> Option<&mut BuildJobResult> {
        self.info.get_mut(addr)
    }
}

impl_serdeany!(ArtifactInfoMetadata);


#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use super::*;

    // #[test]
    // fn test_from_json_url() {
    //     let url = "https://storage.googleapis.com/faas_bucket_1/client_builds/fc0fc148-0e8e-4352-9f5f-d49f9fd421c1-results.json?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Credential=client-project-rw%40adept-vigil-394020.iam.gserviceaccount.com%2F20230821%2Fauto%2Fstorage%2Fgoog4_request&X-Goog-Date=20230821T040509Z&X-Goog-Expires=259200&X-Goog-SignedHeaders=host&X-Goog-Signature=09b8e8e4b92400e58d15e7f20f97c44ce5c7903e3bf251c6a3ce92a645cc0b9080bc6a58e39fbb10d3ac9835b53c98d51b1fdf9ea6c795bb4dfcb303ea2a41fd851f984ad67b9590d6f4a98300431a009b47c4797c8731de50a8525613d8d7f8b01cd4e5af05e8278207cdfb563149bdbb1d8f632bb7737a2bacba1c28a4116f6164519c13d9c49fe6fee43b40bd6db844bc9ac601e9b55259b7405bdcfbdee6fbe3f9e0f64e69a2656935a8b86997634a0df1fcd2c1c7a4914a24899b6db2e63c4bede49d6cd49a1cc07359357abc33d8acd76ba8ee8061281f1d566f3cd480eacff374c188090a2d336f02a199907ef7b81f00eb11ed1fe33f7c807903656c";
    //     let result = BuildJobResult::from_json_url(url.to_string()).expect("get result failed");
    //     println!("{:?}", result);
    // }
    //
    // #[test]
    // fn test_submit_onchain_job() {
    //     let addr = EVMAddress::from_str("0xf3ae5d769e153ef72b4e3591ac004e89f48107a1");
    //     let chain = Chain::ETH;
    //
    //     let job = BuildJob::submit_onchain_job(chain, addr.unwrap()).expect("submit onchain job failed");
    //     println!("{:?}", job.id);
    // }
    //
    // #[test]
    // fn test_wait_build_job() {
    //     let job = JobContext::new("fc0fc148-0e8e-4352-9f5f-d49f9fd421c1".to_string());
    //     let result = job.wait_build_job().expect("wait build job failed");
    //     println!("{:?}", result.abi);
    // }
}