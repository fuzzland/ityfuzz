/// Configuration for the EVM fuzzer
use crate::evm::contract_utils::{ContractInfo, ContractLoader};
use crate::evm::onchain::endpoints::{OnChainConfig, PriceOracle};

use crate::evm::blaz::builder::BuildJob;
use crate::evm::blaz::offchain_artifacts::OffChainArtifact;
use crate::evm::blaz::offchain_config::OffchainConfig;
use crate::evm::oracles::erc20::IERC20OracleFlashloan;
use crate::evm::types::EVMAddress;
use crate::oracle::{Oracle, Producer};
use std::cell::RefCell;
use std::collections::HashSet;
use std::fmt::{self, Debug};
use std::fs::File;
use std::rc::Rc;

pub enum FuzzerTypes {
    CMP,
    DATAFLOW,
    BASIC,
}

#[derive(Copy, Clone)]
pub enum StorageFetchingMode {
    Dump,
    OneByOne,
}

impl StorageFetchingMode {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "dump" => Some(StorageFetchingMode::Dump),
            "onebyone" => Some(StorageFetchingMode::OneByOne),
            _ => None,
        }
    }
}

impl FuzzerTypes {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "cmp" => Ok(FuzzerTypes::CMP),
            "dataflow" => Ok(FuzzerTypes::DATAFLOW),
            "basic" => Ok(FuzzerTypes::BASIC),
            _ => Err(format!("Unknown fuzzer type: {}", s)),
        }
    }
}

pub struct Config<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, CI> {
    pub onchain: Option<OnChainConfig>,
    pub onchain_storage_fetching: Option<StorageFetchingMode>,
    pub flashloan: bool,
    pub concolic: bool,
    pub concolic_caller: bool,
    pub concolic_timeout: u32,
    pub concolic_num_threads: usize,
    pub fuzzer_type: FuzzerTypes,
    pub contract_loader: ContractLoader,
    pub oracle: Vec<Rc<RefCell<dyn Oracle<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, CI>>>>,
    pub producers: Vec<Rc<RefCell<dyn Producer<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, CI>>>>,
    pub price_oracle: Box<dyn PriceOracle>,
    pub replay_file: Option<String>,
    pub flashloan_oracle: Rc<RefCell<IERC20OracleFlashloan>>,
    pub selfdestruct_oracle: bool,
    pub reentrancy_oracle: bool,
    pub state_comp_oracle: Option<String>,
    pub state_comp_matching: Option<String>,
    pub work_dir: String,
    pub write_relationship: bool,
    pub run_forever: bool,
    pub sha3_bypass: bool,
    pub base_path: String,
    pub echidna_oracle: bool,
    pub invariant_oracle: bool,
    pub panic_on_bug: bool,
    pub spec_id: String,
    pub only_fuzz: HashSet<EVMAddress>,
    pub typed_bug: bool,
    pub selfdestruct_bug: bool,
    pub arbitrary_external_call: bool,
    pub integer_overflow_oracle: bool,
    pub builder: Option<BuildJob>,
    pub local_files_basedir_pattern: Option<String>,
    #[cfg(feature = "use_presets")]
    pub preset_file_path: String,
}

impl<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, CI> Debug
    for Config<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, CI>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("onchain", &self.onchain)
            // .field("onchain_storage_fetching", &self.onchain_storage_fetching)
            .field("flashloan", &self.flashloan)
            .field("concolic", &self.concolic)
            .field("concolic_caller", &self.concolic_caller)
            // .field("fuzzer_type", &self.fuzzer_type)
            .field("contract_loader", &self.contract_loader)
            // .field("oracle", &self.oracle)
            // .field("producers", &self.producers)
            .field("price_oracle", &self.price_oracle)
            .field("replay_file", &self.replay_file)
            // .field("flashloan_oracle", &self.flashloan_oracle)
            .field("selfdestruct_oracle", &self.selfdestruct_oracle)
            .field("state_comp_oracle", &self.state_comp_oracle)
            .field("state_comp_matching", &self.state_comp_matching)
            .field("work_dir", &self.work_dir)
            .field("write_relationship", &self.write_relationship)
            .field("run_forever", &self.run_forever)
            .field("sha3_bypass", &self.sha3_bypass)
            .field("base_path", &self.base_path)
            .field("echidna_oracle", &self.echidna_oracle)
            .field("panic_on_bug", &self.panic_on_bug)
            .field("spec_id", &self.spec_id)
            .field("only_fuzz", &self.only_fuzz)
            .field("typed_bug", &self.typed_bug)
            .field("selfdestruct_bug", &self.selfdestruct_bug)
            .field("cheatcode", &self.cheatcode)
            // .field("builder", &self.builder)
            .finish()
    }
}
