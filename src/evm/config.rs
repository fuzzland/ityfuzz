use crate::evm::contract_utils::ContractInfo;
use crate::evm::onchain::endpoints::OnChainConfig;
use crate::evm::onchain::flashloan::Flashloan;
use crate::oracle::Oracle;

pub enum FuzzerTypes {
    CMP,
    DATAFLOW,
    BASIC,
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
    pub flashloan: bool,
    pub concolic_prob: Option<f32>,
    pub fuzzer_type: FuzzerTypes,
    pub contract_info: Vec<ContractInfo>,
    pub oracle: Vec<Box<dyn Oracle<VS, Addr, Code, By, Loc, SlotTy, Out, I, S>>>,
}
