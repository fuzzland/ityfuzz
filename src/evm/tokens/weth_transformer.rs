use std::fmt::Debug;

use alloy_primitives::hex;
use bytes::Bytes;
use libafl::schedulers::Scheduler;
use revm_interpreter::{Contract, Interpreter};
use serde::{de::DeserializeOwned, Serialize};

use super::{uniswap::CODE_REGISTRY, PairContext};
use crate::{
    evm::{
        types::{EVMAddress, EVMFuzzState, EVMU256, EVMU512},
        vm::EVMExecutor,
    },
    generic_vm::vm_state::VMStateT,
    get_code_tokens,
    input::ConciseSerde,
    is_call_success,
    scale,
};

#[derive(Clone, Debug, Default)]
pub struct WethContext {
    pub weth_address: EVMAddress,
}

pub fn withdraw_bytes(amount: EVMU256) -> Bytes {
    let mut ret = Vec::new();
    ret.extend_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]); // transfer to null
    ret.extend_from_slice(&[0x00; 32]); // padding
    ret.extend_from_slice(&amount.to_be_bytes::<32>()); // amount
    Bytes::from(ret)
}

impl PairContext for WethContext {
    fn transform<VS, CI, SC, DB>(
        &self,
        src: &EVMAddress,
        next: &EVMAddress,
        amount: EVMU256,
        state: &mut EVMFuzzState,
        vm: &mut EVMExecutor<VS, CI, SC, DB>,
        reverse: bool,
    ) -> Option<(EVMAddress, EVMU256)>
    where
        VS: VMStateT + Default + 'static,
        CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde + 'static,
        SC: Scheduler<State = EVMFuzzState> + Clone + 'static,
    {
        if reverse {
            // println!("bought {:?} weth", amount);
            // buy
            vm.host.evmstate.flashloan_data.owed += EVMU512::from(amount) * scale!();
            vm.host
                .evmstate
                .flashloan_data
                .oracle_recheck_balance
                .insert(self.weth_address);
        } else {
            // println!("sold {:?} weth", amount);
            // sell
            vm.host.evmstate.flashloan_data.earned += EVMU512::from(amount) * scale!();
            vm.host
                .evmstate
                .flashloan_data
                .oracle_recheck_balance
                .insert(self.weth_address);
        }

        // todo: fix real balance
        vm.host.evmstate.balance.insert(self.weth_address, EVMU256::MAX);

        let addr = self.weth_address;
        let code = get_code_tokens!(addr, vm, state);
        // let call = Contract::new_with_context_analyzed(
        //     if reverse {
        //         // buy
        //         Bytes::from(vec![])
        //     } else {
        //         // sell
        //         withdraw_bytes(amount)
        //     },
        //     code,
        //     &CallContext {
        //         address: addr,
        //         caller: if reverse { *next } else { *src },
        //         code_address: addr,
        //         apparent_value: if reverse { amount } else { EVMU256::ZERO },
        //         scheme: CallScheme::Call,
        //     },
        // );
        let call = Contract::new(
            if reverse {
                // buy
                Bytes::from(vec![]).into()
            } else {
                // sell
                withdraw_bytes(amount).into()
            },
            *code,
            None,
            addr,
            if reverse { *next } else { *src },
            if reverse { amount } else { EVMU256::ZERO },
        );
        let mut interp = Interpreter::new(call.clone(), 1e10 as u64, false);
        let ir = vm.host.run_inspect(&mut interp, state);
        if !is_call_success!(ir) {
            println!(
                "call: {:?} => {:?} {:?}",
                call.caller,
                call.target_address,
                hex::encode(call.input)
            );
            // panic!("Weth call failed: {:?} {:?}", ir, interp.return_value());
            panic!("Weth call failed: {:?} {:?}", ir, interp.return_data_buffer);
        }

        Some((*next, amount))
    }

    fn name(&self) -> String {
        "weth".to_string()
    }
}
