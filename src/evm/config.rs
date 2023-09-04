/// Configuration for the EVM fuzzer
use crate::evm::contract_utils::{ContractInfo, ContractLoader};
use crate::evm::onchain::endpoints::{OnChainConfig, PriceOracle};

use crate::evm::oracles::erc20::IERC20OracleFlashloan;
use crate::oracle::{Oracle, Producer};
use std::cell::RefCell;
use std::collections::HashSet;
use std::fs::File;
use std::rc::Rc;
use crate::evm::blaz::builder::BuildJob;
use crate::evm::blaz::offchain_artifacts::OffChainArtifact;
use crate::evm::blaz::offchain_config::OffchainConfig;
use crate::evm::types::EVMAddress;

pub enum FuzzerTypes {
    CMP,
    DATAFLOW,
    BASIC,
}

pub enum StorageFetchingMode {
    Dump,
    All,
    OneByOne,
}

impl StorageFetchingMode {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "dump" => Some(StorageFetchingMode::Dump),
            "all" => Some(StorageFetchingMode::All),
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
    pub fuzzer_type: FuzzerTypes,
    pub contract_loader: ContractLoader,
    pub oracle: Vec<Rc<RefCell<dyn Oracle<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, CI>>>>,
    pub producers: Vec<Rc<RefCell<dyn Producer<VS, Addr, Code, By, Loc, SlotTy, Out, I, S, CI>>>>,
    pub price_oracle: Box<dyn PriceOracle>,
    pub replay_file: Option<String>,
    pub flashloan_oracle: Rc<RefCell<IERC20OracleFlashloan>>,
    pub selfdestruct_oracle: bool,
    pub state_comp_oracle: Option<String>,
    pub state_comp_matching: Option<String>,
    pub work_dir: String,
    pub write_relationship: bool,
    pub run_forever: bool,
    pub sha3_bypass: bool,
    pub base_path: String,
    pub echidna_oracle: bool,
    pub panic_on_bug: bool,
    pub spec_id: String,
    pub only_fuzz: HashSet<EVMAddress>,
    pub typed_bug: bool,
    pub selfdestruct_bug: bool,
    pub arbitrary_external_call: bool,
    pub builder: Option<BuildJob>,
}
