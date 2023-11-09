use std::{collections::HashSet, fmt::Debug, str::FromStr};

use libafl::{
    inputs::Input,
    prelude::{HasCorpus, HasMetadata, State},
    schedulers::Scheduler,
};
use revm_interpreter::Interpreter;
use revm_primitives::{keccak256, B256};
use serde::Serialize;
use tracing::{debug, info};

use crate::{
    evm::{
        host::FuzzHost,
        input::{ConciseEVMInput, EVMInputT},
        middlewares::middleware::{Middleware, MiddlewareType},
        onchain::endpoints::{Chain, OnChainConfig},
        types::EVMAddress,
        uniswap::{get_uniswap_info, UniswapProvider},
    },
    generic_vm::vm_state::VMStateT,
    input::VMInputT,
    state::{HasCaller, HasCurrentInputIdx, HasItyState},
};

#[derive(Serialize, Debug, Clone, Default)]
pub struct IntegerOverflowMiddleware {
    whitelist: HashSet<EVMAddress>,
    pub fp: HashSet<(EVMAddress, usize, &'static str)>,
    pair_hash: B256,
}

impl IntegerOverflowMiddleware {
    pub fn new(onchain: Option<OnChainConfig>) -> Self {
        if let Some(OnChainConfig { chain_name, .. }) = onchain {
            let chain = &Chain::from_str(&chain_name).unwrap();
            let info = get_uniswap_info(&UniswapProvider::UniswapV2, chain);
            let whitelist = HashSet::from([info.router]);
            let pair_hash = keccak256(&info.pair_bytecode);
            println!("pair_hash: {:?}", pair_hash);
            return Self {
                whitelist,
                fp: HashSet::new(),
                pair_hash,
            };
        }
        Self::default()
    }
}

impl<I, VS, S, SC> Middleware<VS, I, S, SC> for IntegerOverflowMiddleware
where
    I: Input + VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT + 'static,
    VS: VMStateT,
    S: State
        + HasCaller<EVMAddress>
        + HasCorpus
        + HasItyState<EVMAddress, EVMAddress, VS, ConciseEVMInput>
        + HasMetadata
        + HasCurrentInputIdx
        + Debug
        + Clone,
    SC: Scheduler<State = S> + Clone,
{
    unsafe fn on_step(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<VS, I, S, SC>, _state: &mut S) {
        let addr = interp.contract.code_address;
        let pc = interp.program_counter();
        macro_rules! check {
            ($overflow_fn: ident, $op: expr, $is_div: expr) => {
                let (l, r) = (interp.stack.peek(0).unwrap(), interp.stack.peek(1).unwrap());
                let div = if $is_div { l < r } else { l.$overflow_fn(r).1 };
                if !self.whitelist.contains(&interp.contract.code_address) &&
                    div &&
                    !host.current_integer_overflow.contains(&(addr, pc, $op)) &&
                    !self.fp.contains(&(addr, pc, $op))
                {
                    let bytecode = host.code.get(&addr).unwrap();
                    if bytecode.hash() == self.pair_hash {
                        // add whitelist for uniswap pair
                        self.whitelist.insert(addr);
                        info!("add overflow whitelist for uniswap pair: {:?}", addr);
                    } else {
                        // println!("bytecode:{addr:?} {:?}", hex::encode(bytecode.bytecode()));
                        info!("contract {:?} overflow on pc[{pc:x}]: {} {} {}", addr, l, $op, r);
                        host.current_integer_overflow.insert((addr, pc, $op));
                    }
                }
            };
        }
        match *interp.instruction_pointer {
            0x01 => {
                // +ADD
                check!(overflowing_add, "+", false);
            }
            0x02 => {
                // *MUL
                check!(overflowing_mul, "*", false);
            }
            0x03 => {
                // -SUB
                check!(overflowing_sub, "-", false);
            }
            0x04 | 0x05 => {
                // DIV/ SDIV
                // overflowing_add for placeholder, not used
                check!(overflowing_add, "/", true);
            }
            0x0a => {
                // ** EXP
                check!(overflowing_pow, "**", false);
            }
            _ => {}
        }
    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::IntegerOverflow
    }
}

#[cfg(test)]
mod test {

    #[test]
    fn test_merge() {}
}
