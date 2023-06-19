use crate::{
    evm::{
        host::{FuzzHost, GLOBAL_CALL_CONTEXT, STATE_CHANGE},
        input::EVMInputT,
        vm::EVMState,
    },
    generic_vm::vm_state::VMStateT,
    input::VMInputT,
    state::{HasCaller, HasCurrentInputIdx, HasItyState},
    state_input::StagedVMState,
    tracer::{BasicTxn, TxnTrace},
};
use bytes::Bytes;
use libafl::state::{HasCorpus, HasMetadata, State};
use libafl::prelude::HasRand;

use revm_interpreter::{CallContext, CallScheme, Contract, Host, Interpreter};

use std::{fmt::Debug, marker::PhantomData};
use revm_primitives::{LatestSpec, SpecId};
use crate::evm::types::{EVMAddress, EVMU256};

#[derive(Clone, Debug)]
pub struct SymbolicMemory {}

#[derive(Clone, Debug)]
pub struct ConcolicExeHost<Loc, Addr, VS>
where
    VS: Default + VMStateT,
    Addr: Debug,
    Loc: Debug,
{
    memory: SymbolicMemory,
    initial_state: StagedVMState<Loc, Addr, VS>,
    transactions: TxnTrace<Loc, Addr>,
    current_state: StagedVMState<Loc, Addr, VS>,
}

#[derive(Debug, Clone)]
pub struct ConcolicEVMExecutor<I, S, VS>
where
    S: State + HasCaller<EVMAddress> + Debug + Clone + 'static,
    I: VMInputT<VS, EVMAddress, EVMAddress> + EVMInputT,
    VS: VMStateT,
{
    pub host: FuzzHost<VS, I, S>,
    pub concolic_exe_host: ConcolicExeHost<EVMAddress, EVMAddress, VS>,
    deployer: EVMAddress,
    contract_addr: EVMAddress,
    phandom: PhantomData<(I, S, VS)>,
}

impl<I, S, VS> ConcolicEVMExecutor<I, S, VS>
where
    S: State + HasCaller<EVMAddress> + Debug + Clone + 'static,
    I: VMInputT<VS, EVMAddress, EVMAddress> + EVMInputT,
    VS: VMStateT,
{
    pub fn new(
        mut host: FuzzHost<VS, I, S>,
        deployer: EVMAddress,
        contract_addr: EVMAddress,
        transactions: TxnTrace<EVMAddress, EVMAddress>,
    ) -> Self {
        host.evmstate = EVMState::new();
        Self {
            host,
            concolic_exe_host: ConcolicExeHost {
                memory: SymbolicMemory {},
                initial_state: StagedVMState::new_uninitialized(),
                transactions: transactions,
                current_state: StagedVMState::new_uninitialized(),
            },
            contract_addr,
            deployer,
            phandom: PhantomData,
        }
    }

    pub fn proceed() {}
}

impl<VS, I, S> ConcolicEVMExecutor<I, S, VS>
where
    I: VMInputT<VS, EVMAddress, EVMAddress> + EVMInputT + 'static,
    S: State
        + HasRand
        + HasCorpus<I>
        + HasItyState<EVMAddress, EVMAddress, VS>
        + HasMetadata
        + HasCaller<EVMAddress>
        + HasCurrentInputIdx
        + Default
        + Clone
        + Debug
        + 'static,
    VS: VMStateT + Default + 'static,
{
    pub fn execute_all(&mut self, state: &mut S) {
        // the clone here is not optimal, how can we not clone and pass the borrow checker?
        let txns = self.concolic_exe_host.transactions.transactions.clone();
        for txn in txns.iter() {
            self.execute_one_txn(txn.clone(), state);
        }
    }

    pub fn execute_one_txn(&mut self, input: BasicTxn<EVMAddress>, state: &mut S) {
        let contract = input.contract;
        let caller = input.caller;
        let value = input.value;
        self.execute_with_concolic(
            &CallContext {
                address: contract,
                caller,
                code_address: contract,
                apparent_value: value.unwrap_or(EVMU256::ZERO),
                scheme: CallScheme::Call,
            },
            Bytes::from(
                input
                    .data_abi
                    .expect("No data abi in transaction trace")
                    .b
                    .get_bytes(),
            ),
            state,
        )
    }

    pub fn execute_with_concolic(&mut self, call_ctx: &CallContext, data: Bytes, state: &mut S) {
        self.host.coverage_changed = false;

        unsafe {
            GLOBAL_CALL_CONTEXT = Some(call_ctx.clone());
        }

        let bytecode = self
            .host
            .code
            .get(&call_ctx.code_address)
            .expect("no code")
            .clone();

        let mut interp = {
            let call =
                Contract::new_with_context_analyzed(data, bytecode, call_ctx);
            Interpreter::new(call, 1e10 as u64, false)
        };
        unsafe {
            STATE_CHANGE = false;
        }

        // let _r = interp.run::<FuzzHost<VS, I, S>, LatestSpec, S>(&mut self.host, state);

        // remove all concolic hosts
        self.host.remove_all_middlewares();
    }
}
