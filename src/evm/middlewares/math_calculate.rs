use std::{collections::HashSet, fmt::Debug, str::FromStr};

use libafl::schedulers::Scheduler;
use revm_interpreter::Interpreter;
use revm_primitives::{keccak256, B256};
use serde::Serialize;
use tracing::{debug, info};

use crate::evm::{
    host::FuzzHost,
    middlewares::middleware::{Middleware, MiddlewareType},
    onchain::endpoints::{Chain, OnChainConfig},
    srcmap::{SourceCodeResult, SOURCE_MAP_PROVIDER},
    types::{EVMAddress, EVMFuzzState},
    uniswap::{get_uniswap_info, UniswapProvider},
};

#[derive(Serialize, Debug, Clone, Default)]
pub struct MathCalculateMiddleware {
    report_when_no_srcmap: bool,
    whitelist: HashSet<EVMAddress>,
    pub fp: HashSet<(EVMAddress, usize)>,
    pair_hash: B256,
}

impl MathCalculateMiddleware {
    pub fn new(onchain: Option<OnChainConfig>, report_when_no_srcmap: bool) -> Self {
        if let Some(OnChainConfig { chain_name, .. }) = onchain {
            let chain = &Chain::from_str(&chain_name).unwrap();
            let info = get_uniswap_info(&UniswapProvider::UniswapV2, chain);
            let whitelist = HashSet::from([info.router]);
            let pair_hash = keccak256(&info.pair_bytecode);
            println!("pair_hash: {:?}", pair_hash);
            return Self {
                report_when_no_srcmap,
                whitelist,
                fp: HashSet::new(),
                pair_hash,
            };
        }
        Self::default()
    }
}

impl<SC> Middleware<SC> for MathCalculateMiddleware
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    unsafe fn on_step(&mut self, interp: &mut Interpreter, host: &mut FuzzHost<SC>, _state: &mut EVMFuzzState) {
        let addr = interp.contract.code_address;
        let pc = interp.program_counter();
        macro_rules! check {
            ($overflow_fn: ident, $op: expr) => {
                if self.whitelist.contains(&interp.contract.code_address) {
                    return;
                }
                let (l, r) = (interp.stack.peek(0).unwrap(), interp.stack.peek(1).unwrap());
                let overflow = if $op == "/" {l < r || r == alloy_primitives::Uint::ZERO } else { l.$overflow_fn(r).1 };
                if !overflow ||
                // already in fp
                    self.fp.contains(&(addr, pc)) ||
                // already reported
                host.current_math_error.contains(&(addr, pc, $op))
                {
                    return;
                }
                let bytecode = host.code.get(&addr).unwrap();
                if bytecode.hash() == self.pair_hash {
                    // add whitelist for uniswap pair
                    debug!("add overflow whitelist for uniswap pair: {:?}", addr);
                    self.whitelist.insert(addr);
                    return;
                }
                match  SOURCE_MAP_PROVIDER.lock().unwrap().get_source_code(&addr, pc) {
                    SourceCodeResult::NoSourceMap => {
                        // no srcmap
                        if self.report_when_no_srcmap {
                            info!("contract {:?} maybe math error on pc[{pc:x}]: {} {} {}", addr, l, $op, r);
                            host.current_math_error.insert((addr, pc, $op));
                        } else {
                            self.fp.insert((addr, pc));
                        }
                    }
                    SourceCodeResult::NoSourceCode |  SourceCodeResult::SourceCodeNoPcMatch(_) => {
                        // fp because of solc generated code
                        self.fp.insert((addr, pc));
                    }
                    SourceCodeResult::SourceCode(source_code) => {
                        if let Some(pos) = source_code.find($op) && pos != 0 {
                            // real bug
                            if host.current_math_error.contains(&(addr, pc, $op)) {
                                // already reported
                                return;
                            }
                            info!("contract {:?} math error on pc[{pc:x}]: {} {} {} {source_code:?}", addr, l, $op, r);
                            host.current_math_error.insert((addr, pc, $op));
                        } else {
                            // fp
                            self.fp.insert((addr, pc));
                        }
                    }
                }
            };
        }
        match *interp.instruction_pointer {
            0x01 => {
                // +ADD
                check!(overflowing_add, "+");
            }
            0x02 => {
                // *MUL
                check!(overflowing_mul, "*");
            }
            0x03 => {
                // -SUB
                check!(overflowing_sub, "-");
            }
            0x04 | 0x05 => {
                // DIV/ SDIV
                // overflowing_add for placeholder, not used
                check!(overflowing_add, "/");
            }
            0x0a => {
                // ** EXP
                check!(overflowing_pow, "**");
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
