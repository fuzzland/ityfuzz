use std::{
    collections::{BTreeMap, HashMap},
    default::Default,
    str::FromStr,
};

use alloy_sol_types::SolValue;
use bytes::Bytes;
use ethers::{
    abi::{ethereum_types, AbiEncode},
    prelude::{Provider, ProviderExt},
    providers::Middleware,
    types::{AccountState, Address, Transaction, U256, U64},
};
use foundry_cheatcodes::Vm::VmCalls::rpc;
use libafl::prelude::{Scheduler, StdMapObserver};
use parquet::{
    file::reader::{FileReader, SerializedFileReader},
    record::{Field, Row},
};
use primitive_types::H256;
use revm_interpreter::BytecodeLocked;
use revm_primitives::{BlockEnv, Bytecode, Env, B160};
use tracing::debug;

use crate::evm::{
    abi::BoxedABI,
    input::{ConciseEVMInput, EVMInput, EVMInputTy::ABI},
    onchain::endpoints::{
        Chain::{BSC, ETH},
        OnChainConfig,
    },
    types::EVMAddress,
};

pub type CryoTestcases = Vec<Vec<ConciseEVMInput>>;

#[derive(Clone, Debug, Default)]
pub struct OffchainCor;

impl OffchainCor {
    pub async fn get_call_env(rpc_url: &str, tx_hash: String) -> Env {
        let provider = Provider::try_connect(rpc_url).await.expect("rpc connect error");
        let req = H256::from_str(tx_hash.as_str()).unwrap();
        let tx = provider
            .get_transaction(req)
            .await
            .expect("tx_hash or rpc error")
            .unwrap();
        let block_id = tx.block_number.unwrap().as_u64();
        let block_rep = provider
            .get_block(block_id)
            .await
            .expect("block_number error ")
            .unwrap();
        println!("block number is {:?}", tx.block_number.unwrap().as_usize());
        let block_env = BlockEnv {
            number: U256::from(tx.block_number.unwrap().as_usize()).into(),
            coinbase: Default::default(),
            timestamp: block_rep.clone().timestamp.into(),
            difficulty: block_rep.clone().difficulty.into(),
            prevrandao: None,
            basefee: Default::default(),
            gas_limit: Default::default(),
        };
        Env {
            cfg: Default::default(),
            block: block_env,
            tx: Default::default(),
        }
    }

    pub async fn get_transaction(rpc_url: &str, tx_hash: String) -> ConciseEVMInput {
        let provider = Provider::try_connect(rpc_url).await.expect("rpc connect error");
        let req = H256::from_str(tx_hash.as_str()).unwrap();
        let env = Self::get_call_env(rpc_url, tx_hash).await;
        let tx_info = provider.get_transaction(req).await.expect("rpc error").unwrap();
        let abi_data = BoxedABI::default();
        let to_address = B160::from_slice(&tx_info.to.unwrap().0);
        ConciseEVMInput {
            input_type: ABI,
            caller: tx_info.from.into(),
            contract: to_address,
            #[cfg(not(feature = "debug"))]
            data: Some(abi_data),
            txn_value: Some(tx_info.value.into()),
            step: false,
            env,
            liquidation_percent: 0,
            randomness: vec![],
            repeat: 1,
            layer: 0,
            call_leak: 0,
            return_data: None,
            swap_data: Default::default(),
            #[cfg(feature = "debug")]
            direct_data: tx_info.input.to_string(),
        }
    }

    pub fn generate_testcases_from_txhash(rpc_url: &str, tx_hash: String) -> CryoTestcases {
        let mut cryo_testcases = vec![];
        let mut test_case: Vec<ConciseEVMInput> = vec![];
        let rt = tokio::runtime::Runtime::new().unwrap();
        let tx_input = rt.block_on(OffchainCor::get_transaction(rpc_url, tx_hash));
        test_case.push(tx_input);
        cryo_testcases.push(test_case);
        cryo_testcases
    }
}

mod test {
    use revm_primitives::Env;

    use crate::evm::blaz::offchain_cor::OffchainCor;
}
