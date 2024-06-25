use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashMap},
    default::Default,
    fs::File,
    path::Path,
    process,
    str::FromStr,
    sync::Arc,
};

use alloy_primitives::{BlockNumber, B256};
use alloy_sol_types::SolValue;
use bytes::Bytes;
use ethers::{
    abi::{ethereum_types, AbiEncode},
    prelude::{
        CallFrame,
        GethDebugBuiltInTracerConfig,
        GethDebugBuiltInTracerType,
        GethDebugBuiltInTracerType::PreStateTracer,
        GethDebugTracerConfig,
        GethDebugTracerType,
        GethDebugTracingOptions,
        Http,
        PreStateConfig,
        PreStateFrame,
        Provider,
        ProviderExt,
    },
    providers::Middleware,
    types::{AccountState, Address, Transaction, U256, U64},
};
use libafl::prelude::{Scheduler, StdMapObserver};
use parquet::{
    file::reader::{FileReader, SerializedFileReader},
    record::{Field, Row},
};
use primitive_types::H256;
use revm_interpreter::BytecodeLocked;
use revm_primitives::{BlockEnv, Bytecode, Env};

use crate::{
    evm::{
        abi::{get_abi_type_boxed, BoxedABI},
        contract_utils::to_hex_string,
        host::FuzzHost,
        input::{ConciseEVMInput, EVMInput, EVMInputTy::ABI},
        scheduler::PowerABIScheduler,
        types::{EVMAddress, EVMFuzzState, EVMStagedVMState},
        vm::EVMState,
        EVMU256,
    },
    executor::FuzzExecutor,
};

pub type GethStateUpdate = BTreeMap<Address, AccountState>;
#[derive(Clone, Debug, Default)]
pub struct ActionTransaction {
    action_from: Option<String>,
    action_to: Option<String>,
    action_value: Option<String>,
    action_gas: Option<u32>,
    action_input: Option<String>,
    action_call_type: Option<String>,
    action_init: Option<String>,
    action_reward_type: Option<String>,
    action_type: Option<String>,
    result_gas_used: Option<u32>,
    result_output: Option<String>,
    result_code: Option<String>,
    result_address: Option<String>,
    trace_address: Option<String>,
    subtraces: Option<u32>,
    transaction_index: Option<u32>,
    transaction_hash: Option<String>,
    block_number: Option<u32>,
    block_hash: Option<String>,
    error: Option<String>,
    chain_id: Option<u64>,
}

pub type CryoTestcases = Vec<(Vec<ConciseEVMInput>, GethStateUpdate)>;

#[derive(Clone, Debug, Default)]
pub struct OffchainCorpus;

impl OffchainCorpus {
    fn parse_row(row: Row) -> ActionTransaction {
        let mut action = ActionTransaction {
            action_from: None,
            action_to: None,
            action_value: None,
            action_gas: None,
            action_input: None,
            action_call_type: None,
            action_init: None,
            action_reward_type: None,
            action_type: None,
            result_gas_used: None,
            result_output: None,
            result_code: None,
            result_address: None,
            trace_address: None,
            subtraces: None,
            transaction_index: None,
            transaction_hash: None,
            block_number: None,
            block_hash: None,
            error: None,
            chain_id: None,
        };

        for (name, field) in row.get_column_iter() {
            match name.as_str() {
                "action_from" => action.action_from = Self::field_to_string(field),
                "action_to" => action.action_to = Self::field_to_string(field),
                "action_value" => action.action_value = Self::field_to_string(field),
                "action_gas" => action.action_gas = Self::field_to_u32(field),
                "action_input" => action.action_input = Self::field_to_string(field),
                "action_call_type" => action.action_call_type = Self::field_to_string(field),
                "action_init" => action.action_init = Self::field_to_string(field),
                "action_reward_type" => action.action_reward_type = Self::field_to_string(field),
                "action_type" => action.action_type = Self::field_to_string(field),
                "result_gas_used" => action.result_gas_used = Self::field_to_u32(field),
                "result_output" => action.result_output = Self::field_to_string(field),
                "result_code" => action.result_code = Self::field_to_string(field),
                "result_address" => action.result_address = Self::field_to_string(field),
                "trace_address" => action.trace_address = Self::field_to_string(field),
                "subtraces" => action.subtraces = Self::field_to_u32(field),
                "transaction_index" => action.transaction_index = Self::field_to_u32(field),
                "transaction_hash" => action.transaction_hash = Self::field_to_string(field),
                "block_number" => action.block_number = Self::field_to_u32(field),
                "block_hash" => action.block_hash = Self::field_to_string(field),
                "error" => action.error = Self::field_to_string(field),
                "chain_id" => action.chain_id = Self::field_to_u64(field),
                _ => (),
            }
        }
        action
    }

    async fn action_transaction_to_tx(rpc_url: &str, ac_txs: &Vec<ActionTransaction>) -> CryoTestcases {
        let mut input = vec![];
        for ac_tx in ac_txs {
            let tx_hash = ac_tx.clone().transaction_hash.unwrap();
            let from = Address::from_str(ac_tx.clone().action_from.unwrap().as_str()).unwrap();
            let to = Address::from_str(ac_tx.clone().action_to.unwrap().as_str()).unwrap();
            let value = if ac_tx.clone().action_value.is_some() {
                EVMU256::from_str(ac_tx.clone().action_value.unwrap().as_str())
            } else {
                Ok(EVMU256::default())
            }
            .unwrap();
            let input_data = ac_tx.clone().action_input.unwrap();
            let abi_data = get_abi_type_boxed(input_data.as_str());
            let env = Self::get_call_env(rpc_url, tx_hash.clone()).await; // rpc req

            let ret = ConciseEVMInput {
                input_type: ABI,
                caller: from.into(),
                contract: to.into(),
                #[cfg(not(feature = "debug"))]
                data: Some(abi_data),
                txn_value: Some(value.into()),
                step: false,
                env,
                liquidation_percent: 0,
                randomness: vec![],
                repeat: 0,
                layer: 0,
                call_leak: 0,
                return_data: None,
                swap_data: Default::default(),
                #[cfg(feature = "debug")]
                direct_data: input_data,
            };

            // gen account state
            let pre_state = Self::pre_state_trace_transaction(rpc_url, tx_hash.clone())
                .await
                .expect("TODO: panic message");
            let testcase = vec![ret];

            input.push((testcase, pre_state));
        }
        input
    }

    fn field_to_string(field: &Field) -> Option<String> {
        match field {
            Field::Bytes(bytes) => Some(to_hex_string(bytes.data())),
            Field::Str(s) => Some(s.to_string()),
            Field::Null => None,
            _ => None,
        }
    }

    fn field_to_u32(field: &Field) -> Option<u32> {
        match field {
            Field::Int(val) => Some(*val as u32),
            Field::Null => None,
            _ => None,
        }
    }

    fn field_to_u64(field: &Field) -> Option<u64> {
        match field {
            Field::Long(val) => Some(*val as u64),
            Field::Null => None,
            _ => None,
        }
    }

    pub fn dfs_call_trace(call_frames: &[CallFrame], transaction: &mut Vec<ConciseEVMInput>, env: Env) {
        for frame in call_frames {
            let abi = BoxedABI::default();
            let txn_value = if frame.clone().value.is_some() {
                Some(U256::from(frame.clone().value.unwrap().encode().as_slice()).into())
            } else {
                None
            };
            let tx = ConciseEVMInput {
                input_type: ABI,
                caller: frame.clone().from.into(),
                contract: frame.clone().to.unwrap().as_address().unwrap().0.into(),
                #[cfg(not(feature = "debug"))]
                data: Some(abi),
                txn_value,
                step: false,
                env: Default::default(),
                liquidation_percent: 0,
                randomness: vec![],
                repeat: 0,
                layer: 0,
                call_leak: 0,
                return_data: None,
                swap_data: Default::default(),
                #[cfg(feature = "debug")]
                direct_data: "".to_string(),
            };
            transaction.push(tx.clone());
        }
    }

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

    pub async fn call_trace_transaction(rpc_url: &str, tx_hash: String) -> CallFrame {
        let provider = Provider::try_connect(rpc_url).await.expect("rpc connect error");
        let req = H256::from_str(tx_hash.as_str()).unwrap();

        let options = GethDebugTracingOptions {
            disable_storage: Some(true),
            enable_memory: Some(false),
            tracer: Some(GethDebugTracerType::BuiltInTracer(
                GethDebugBuiltInTracerType::CallTracer,
            )),
            ..Default::default()
        };

        let tracer_info = provider
            .debug_trace_transaction(req, options)
            .await
            .expect("tracer error");

        let call_tracer = match tracer_info {
            ethers::types::GethTrace::Known(geth_tracer_frame) => match geth_tracer_frame {
                ethers::types::GethTraceFrame::CallTracer(pre_state_frame) => pre_state_frame,
                _ => todo!(),
            },
            _ => todo!(),
        };
        // println!("call_tracer is {:?}", call_tracer);
        call_tracer
    }

    pub async fn pre_state_trace_transaction(rpc_url: &str, tx_hash: String) -> eyre::Result<GethStateUpdate> {
        let provider = Provider::try_connect(rpc_url).await.expect("rpc connect error");
        let req = H256::from_str(tx_hash.as_str()).unwrap();

        let tracer_config =
            GethDebugTracerConfig::BuiltInTracer(GethDebugBuiltInTracerConfig::PreStateTracer(PreStateConfig {
                diff_mode: Some(false),
            }));

        let mut options = GethDebugTracingOptions::default();
        options.tracer = Some(GethDebugTracerType::BuiltInTracer(PreStateTracer));
        options.tracer_config = Some(tracer_config);

        let tracer_info = provider
            .debug_trace_transaction(req, options)
            .await
            .unwrap_or_else(|err| {
                eprintln!("transaction reverted with err: {}", err);
                process::exit(1);
            });

        match tracer_info {
            ethers::types::GethTrace::Known(geth_tracer_frame) => match geth_tracer_frame {
                ethers::types::GethTraceFrame::PreStateTracer(pre_state_frame) => match pre_state_frame {
                    PreStateFrame::Default(default_mode) => Ok(default_mode.0),
                    PreStateFrame::Diff(_) => Ok(GethStateUpdate::default()),
                },
                _ => todo!(),
            },
            _ => todo!(),
        }
    }

    pub async fn generate_testcases_from_txhash(rpc_url: &str, tx_hashs: Vec<String>) -> CryoTestcases {
        let mut cryo_testcases = vec![];
        for tx_hash in tx_hashs {
            let pre_state = Self::pre_state_trace_transaction(rpc_url, tx_hash.clone())
                .await
                .expect("TODO: panic message");
            let call_tracer = Self::call_trace_transaction(rpc_url, tx_hash.clone()).await;
            let vec_call_tracer = vec![call_tracer];
            let mut test_case: Vec<ConciseEVMInput> = vec![];
            let env = Self::get_call_env(rpc_url, tx_hash.clone()).await;
            OffchainCorpus::dfs_call_trace(&vec_call_tracer, &mut test_case, env);
            cryo_testcases.push((test_case, pre_state));
        }
        cryo_testcases
    }

    pub async fn generate_testcases(rpc_url: &str, cryo_parquet_file_path: &str) -> CryoTestcases {
        println!("cryo_parquet_file_path: {:?}", cryo_parquet_file_path);
        let file = File::open(&Path::new(&cryo_parquet_file_path)).expect("Couldn't open parquet data");
        let reader = SerializedFileReader::new(file).unwrap();
        let parquet_metadata = reader.metadata();

        // let num_rows = parquet_metadata.file_metadata().num_rows();
        // println!("Number of rows: {}", num_rows);

        let mut iter = reader.get_row_iter(None).unwrap();
        let mut action_txs = vec![];
        while let Some(record) = iter.next() {
            if record.is_ok() {
                let action = Self::parse_row(record.unwrap());
                if action.action_to.is_none() ||
                    action.transaction_hash.is_none() ||
                    action.action_from.is_none() ||
                    action.action_input.is_none()
                {
                    continue;
                }
                action_txs.push(action);
            }
        }
        let txs = if !action_txs.is_empty() {
            Self::action_transaction_to_tx(rpc_url, &action_txs).await
        } else {
            CryoTestcases::default()
        };
        txs
    }

    pub fn generate_testcases_sync(rpc_url: &str, cryo_parquet_file_path: &str) -> CryoTestcases {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(Self::generate_testcases(rpc_url, cryo_parquet_file_path))
    }

    pub fn generate_vm_state_from_pre_state(tx_state: &(Vec<ConciseEVMInput>, GethStateUpdate)) -> EVMStagedVMState {
        let mut evm_state = EVMStagedVMState::default();
        let state = &tx_state.1;
        let _ = state.into_iter().map(|account_state| {
            let address = account_state.0 .0;
            let address = EVMAddress::from_slice(&address);

            if account_state.1.storage.is_some() {
                let slots = account_state.1.clone().storage.unwrap();
                let accounts_state = slots
                    .into_iter()
                    .map(|item| {
                        let key = EVMU256::from_be_slice(&item.0 .0);
                        let value = EVMU256::from_be_slice(&item.1 .0);
                        (key, value)
                    })
                    .collect();
                evm_state.state.state.insert(address, accounts_state);
            }
        });
        evm_state
    }

    pub fn generate_vm_accounts_from_pre_state(
        rpc_url: &str,
        fuzz_host: &mut FuzzHost<PowerABIScheduler<EVMFuzzState>>,
        cryo_parquet_file_path: &str,
    ) {
        for tx_state in &Self::generate_testcases_sync(rpc_url, cryo_parquet_file_path) {
            // insert account state to host
            let state = &tx_state.1;
            let _ = state.into_iter().map(|account_state| {
                let bytecode = Arc::new(
                    BytecodeLocked::try_from(Bytecode::new_raw(Bytes::from(account_state.1.clone().code.unwrap())))
                        .unwrap(),
                );
                let address = account_state.0 .0;
                let address = EVMAddress::from_slice(&address);
                fuzz_host.code.insert(address, bytecode)
            });
        }
    }
}

mod test {
    use revm_primitives::Env;

    use crate::evm::{blaz::offchain_corpus::OffchainCorpus, input::ConciseEVMInput};

    #[test]
    fn test_new_offchain_corpus() {
        let corpus_path = "/Users/wangchao/work/test_ityfuzz/ityfuzz/tests/init_cryo_corpus/ethereum__traces__18000000_to_18000000.parquet";
        let rpc_url = "https://lb.nodies.app/v1/181a5ebf4c954f8496ae7cbc1ac8d03b";
    }

    #[test]
    fn test_generate_testcases() {
        let rpc_url = "https://lb.nodies.app/v1/181a5ebf4c954f8496ae7cbc1ac8d03b";

        // let testcase = OffchainCorpus::generate_testcases_sync(rpc_url,
        // vec_tx_hash); println!("test_case is {:?}", testcase);
    }

    #[test]
    fn remove_first() {
        let mut items = vec![1, 2, 3];
        items.remove(0);
        println!("after remove items is {:?}", items);
    }
}
