use std::{
    cell::RefCell,
    collections::{hash_map, HashMap},
    fmt::Debug,
    ops::Deref,
    rc::Rc,
    str::FromStr,
    sync::Arc,
};

use alloy_primitives::hex;
use bytes::Bytes;
use libafl::schedulers::Scheduler;
use revm_interpreter::{CallContext, CallScheme, Contract, Interpreter};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use super::{uniswap::CODE_REGISTRY, PairContext, UniswapInfo};
use crate::{
    evm::{
        abi::{A256InnerType, AArray, AEmpty, BoxedABI, A256},
        onchain::endpoints::Chain,
        types::{EVMAddress, EVMFuzzState, EVMU256, EVMU512},
        vm::{EVMExecutor, MEM_LIMIT},
    },
    generic_vm::{
        vm_executor::GenericVM,
        vm_state::{self, VMStateT},
    },
    get_code_tokens,
    input::ConciseSerde,
    is_call_success,
    scale,
};

#[derive(Clone, Debug, Default)]
pub struct WethContext {
    pub weth_address: EVMAddress,
}

impl PairContext for WethContext {
    fn transform<VS, CI, SC>(
        &self,
        src: &EVMAddress,
        next: &EVMAddress,
        amount: EVMU256,
        state: &mut EVMFuzzState,
        vm: &mut EVMExecutor<VS, CI, SC>,
        reverse: bool,
    ) -> Option<(EVMAddress, EVMU256)>
    where
        VS: VMStateT + Default + 'static,
        CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde + 'static,
        SC: Scheduler<State = EVMFuzzState> + Clone + 'static,
    {
        assert!(reverse, "weth transform must be reverse");
        vm.host.evmstate.flashloan_data.owed += EVMU512::from(amount) * scale!();
        vm.host
            .evmstate
            .flashloan_data
            .oracle_recheck_balance
            .insert(self.weth_address);
        let addr = self.weth_address;
        let code = get_code_tokens!(addr, vm);
        let call = Contract::new_with_context_analyzed(
            Bytes::from(vec![]),
            code,
            &CallContext {
                address: addr,
                caller: *next,
                code_address: addr,
                apparent_value: amount,
                scheme: CallScheme::Call,
            },
        );
        let mut interp = Interpreter::new_with_memory_limit(call, 1e10 as u64, false, MEM_LIMIT);
        let ir = vm.host.run_inspect(&mut interp, state);
        if !is_call_success!(ir) {
            return None;
        }
        Some((*src, amount))
    }

    fn name(&self) -> String {
        "weth".to_string()
    }
}
