use std::cell::RefCell;
use std::rc::Rc;
use crate::evm::contract_utils::ContractInfo;
use crate::evm::onchain::endpoints::{OnChainConfig, PriceOracle};
use crate::evm::onchain::flashloan::Flashloan;
use crate::evm::oracle::IERC20OracleFlashloan;
use crate::oracle::Oracle;

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

pub struct Config<VS, Addr, Code, By, Loc, SlotTy, Out, I, S> {
    pub onchain: Option<OnChainConfig>,
    pub onchain_storage_fetching: Option<StorageFetchingMode>,
    pub flashloan: bool,
    pub concolic_prob: Option<f32>,
    pub fuzzer_type: FuzzerTypes,
    pub contract_info: Vec<ContractInfo>,
    pub oracle: Vec<Rc<RefCell<dyn Oracle<VS, Addr, Code, By, Loc, SlotTy, Out, I, S>>>>,
    pub price_oracle: Box<dyn PriceOracle>,
    pub debug_file: Option<String>,
    pub flashloan_oracle: Rc<RefCell<IERC20OracleFlashloan>>,
}
