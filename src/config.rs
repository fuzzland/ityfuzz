use crate::contract_utils::ContractInfo;
use crate::onchain::endpoints::OnChainConfig;
use crate::onchain::flashloan::Flashloan;
use crate::oracle::Oracle;

pub const DEBUG_PRINT_PERCENT: usize = 8000;

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

pub struct Config<'a, I, S> {
    pub onchain: Option<OnChainConfig>,
    pub flashloan: Option<Flashloan<S>>,
    pub fuzzer_type: FuzzerTypes,
    pub contract_info: Vec<ContractInfo>,
    pub oracle: Option<&'a dyn Oracle<I, S>>,
}
