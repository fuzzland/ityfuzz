use std::{collections::HashMap, fmt::Debug, sync::Arc};

use bytes::Bytes;
use libafl::schedulers::Scheduler;
use revm_interpreter::{CallContext, CallScheme, Contract, Interpreter};
use serde::{de::DeserializeOwned, Serialize};

use super::{uniswap::CODE_REGISTRY, PairContext, UniswapInfo};
use crate::{
    evm::{
        types::{EVMAddress, EVMFuzzState, EVMU256},
        vm::{EVMExecutor, MEM_LIMIT},
    },
    generic_vm::vm_state::VMStateT,
    get_code_tokens,
    input::ConciseSerde,
    is_call_success,
};
#[derive(Clone, Debug, Default)]
pub struct UniswapPairContext {
    pub pair_address: EVMAddress,
    pub in_token_address: EVMAddress,
    pub next_hop: EVMAddress,
    pub side: u8,
    pub uniswap_info: Arc<UniswapInfo>,
    pub initial_reserves: (EVMU256, EVMU256),
}

const MAX_RESERVE: u128 = 1 << 112;

impl UniswapPairContext {
    pub fn calculate_amounts_out(&self, amount_in: EVMU256, reserve_in: EVMU256, reserve_out: EVMU256) -> EVMU256 {
        // println!("fee: {}", self.uniswap_info.pool_fee);
        let amount_in_with_fee = amount_in * EVMU256::from(10000 - self.uniswap_info.pool_fee);
        let numerator = amount_in_with_fee * reserve_out;
        let denominator = reserve_in * EVMU256::from(10000) + amount_in_with_fee;
        if denominator == EVMU256::ZERO {
            return EVMU256::ZERO;
        }

        numerator / denominator
    }
}

pub fn reserve_parser(reserve_slot: &EVMU256) -> (EVMU256, EVMU256) {
    let reserve_bytes: [u8; 32] = reserve_slot.to_be_bytes();
    let reserve_1 = EVMU256::try_from_be_slice(&reserve_bytes[4..18]).unwrap();
    let reserve_0 = EVMU256::try_from_be_slice(&reserve_bytes[18..32]).unwrap();
    (reserve_0, reserve_1)
}

pub fn reserve_update(reserve_0: EVMU256, reserve_1: EVMU256) -> EVMU256 {
    let mut ret = vec![0x00; 4];
    // to uint112
    ret.extend_from_slice(&reserve_1.to_be_bytes::<32>()[18..32]);
    ret.extend_from_slice(&reserve_0.to_be_bytes::<32>()[18..32]);
    EVMU256::try_from_be_slice(&ret).unwrap()
}

pub fn transfer_bytes(dst: &EVMAddress, amount: EVMU256) -> Bytes {
    let mut ret = Vec::new();
    ret.extend_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]); // transfer
    ret.extend_from_slice(&[0x00; 12]); // padding
    ret.extend_from_slice(&dst.0); // dst
    ret.extend_from_slice(&amount.to_be_bytes::<32>()); // amount
    Bytes::from(ret)
}

pub fn balance_of_bytes(addr: &EVMAddress) -> Bytes {
    let mut ret = Vec::new();
    ret.extend_from_slice(&[0x70, 0xa0, 0x82, 0x31]); // balanceOf
    ret.extend_from_slice(&[0x00; 12]); // padding
    ret.extend_from_slice(&addr.0); // addr
    Bytes::from(ret)
}

impl UniswapPairContext {
    pub fn initial_transfer<VS, CI, SC>(
        &self,
        src: &EVMAddress,
        next: &EVMAddress,
        amount: EVMU256,
        state: &mut EVMFuzzState,
        vm: &mut EVMExecutor<VS, CI, SC>,
    ) -> Option<()>
    where
        VS: VMStateT + Default + 'static,
        CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde + 'static,
        SC: Scheduler<State = EVMFuzzState> + Clone + 'static,
    {
        let call = Contract::new_with_context_analyzed(
            transfer_bytes(next, amount),
            get_code_tokens!(self.in_token_address, vm, state),
            &CallContext {
                address: self.in_token_address,
                caller: *src,
                code_address: self.in_token_address,
                apparent_value: EVMU256::ZERO,
                scheme: CallScheme::Call,
            },
        );

        let mut interp = Interpreter::new_with_memory_limit(call, 1e10 as u64, false, MEM_LIMIT);
        let ir = vm.host.run_inspect(&mut interp, state);
        if !is_call_success!(ir) {
            // println!("transfer failed1");
            // println!("return value: {:?}", interp.return_value());
            None
        } else {
            // println!("transfer success");
            Some(())
        }
    }
}

impl PairContext for UniswapPairContext {
    fn transform<VS, CI, SC>(
        &self,
        _src: &EVMAddress,
        next: &EVMAddress,
        _amount: EVMU256,
        state: &mut EVMFuzzState,
        vm: &mut EVMExecutor<VS, CI, SC>,
        reverse: bool,
    ) -> Option<(EVMAddress, EVMU256)>
    where
        VS: VMStateT + Default + 'static,
        CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde + 'static,
        SC: Scheduler<State = EVMFuzzState> + Clone + 'static,
    {
        let (in_token_address, out_token_address, side) = if reverse {
            (self.next_hop, self.in_token_address, 1 - self.side)
        } else {
            (self.in_token_address, self.next_hop, self.side)
        };

        let in_token_code = get_code_tokens!(in_token_address, vm, state);
        let out_token_code = get_code_tokens!(out_token_address, vm, state);

        // get balance of pair's token
        macro_rules! balanceof_token {
            ($dir: expr, $who: expr) => {{
                let addr = if $dir { in_token_address } else { out_token_address };
                let call = Contract::new_with_context_analyzed(
                    balance_of_bytes($who),
                    if $dir {
                        in_token_code.clone()
                    } else {
                        out_token_code.clone()
                    },
                    &CallContext {
                        address: addr,
                        caller: EVMAddress::default(),
                        code_address: addr,
                        apparent_value: EVMU256::ZERO,
                        scheme: CallScheme::Call,
                    },
                );
                let mut interp = Interpreter::new_with_memory_limit(call, 1e10 as u64, false, MEM_LIMIT);
                let ir = vm.host.run_inspect(&mut interp, state);
                if !is_call_success!(ir) {
                    return None;
                }
                let in_balance =
                    if let Some(num) = EVMU256::try_from_be_slice(interp.return_value().to_vec().as_slice()) {
                        num
                    } else {
                        // println!("balance of failed");
                        // println!("return value: {:?}", interp.return_value());
                        return None;
                    };

                // println!("balance of {:?}@{:?}: {:?}", $who, addr, in_balance);
                in_balance
            }};
        }

        // transfer in token to pair
        macro_rules! transfer_token {
            ($dir: expr, $who: expr, $dst: expr, $amt: expr) => {{
                let addr = if $dir { in_token_address } else { out_token_address };
                let call = Contract::new_with_context_analyzed(
                    transfer_bytes($dst, $amt),
                    if $dir {
                        in_token_code.clone()
                    } else {
                        out_token_code.clone()
                    },
                    &CallContext {
                        address: addr,
                        caller: $who,
                        code_address: addr,
                        apparent_value: EVMU256::ZERO,
                        scheme: CallScheme::Call,
                    },
                );

                // println!("transfer {:?}@{:?} for {:?} => {:?}", $amt, addr, $who, $dst);
                // println!("pre_vm_state: {:?}", vm.host.evmstate.state);

                let mut interp = Interpreter::new_with_memory_limit(call, 1e10 as u64, false, MEM_LIMIT);

                let ir = vm.host.run_inspect(&mut interp, state);
                // println!("bytes: {:?}", transfer_bytes($dst, $amt));
                // println!("from: {:?} => {:?}, {:?}", $who, $dst, addr);
                if !is_call_success!(ir) {
                    // println!("transfer failed2");
                    // println!("return value: {:?}", interp.return_value());
                    return None;
                }
                // println!("transfer success");
            }};
        }

        // 0. ensure not locked, check unlock slot at 0xc
        if let Some(slots) = vm.host.evmstate.state.get(&self.pair_address) {
            if let Some(slot) = slots.get(&EVMU256::from(0xc)) {
                if *slot == EVMU256::ZERO {
                    // locked
                    return None;
                }
            }
        }

        // 1. get balance of pair's token
        let reserve_slot = vm
            .host
            .evmstate
            .state
            .get(&self.pair_address)
            .map(|x| x.get(&EVMU256::from(8)));

        let reserve = if let Some(Some(reserve_slot)) = &reserve_slot {
            reserve_parser(reserve_slot)
        } else {
            (self.initial_reserves.0, self.initial_reserves.1)
        };
        let reserve_in = if side == 0 { reserve.0 } else { reserve.1 };
        let reserve_out = if side == 0 { reserve.1 } else { reserve.0 };

        // 2. get balance of pair's token
        let new_balance = balanceof_token!(true, &self.pair_address);
        balanceof_token!(false, &self.pair_address);

        // 3. calculate amount out
        let amount_in = new_balance - reserve_in;

        // println!("original balance: {:?}", reserve_in);
        // println!("new balance: {:?}", new_balance);

        let amount_out = self.calculate_amounts_out(amount_in, reserve_in, reserve_out);

        // 3.5 transfer out token
        let original_balance = balanceof_token!(false, next);
        transfer_token!(false, self.pair_address, next, amount_out);

        // 4. update reserve
        let new_reserve_0 = if side == 0 {
            new_balance
        } else {
            balanceof_token!(false, &self.pair_address)
        };
        let new_reserve_1 = if side == 0 {
            balanceof_token!(false, &self.pair_address)
        } else {
            new_balance
        };

        let max_reserve = EVMU256::from(MAX_RESERVE);
        if new_reserve_0 > max_reserve || new_reserve_1 > max_reserve {
            return None;
        }

        // #[cfg(test)]
        // {
        //     println!("amount in: {:?}", amount_in);
        //     println!("amount out: {:?}", amount_out);
        //     println!("orginal reserve: {:?}", reserve);
        //     println!("new reserve: {:?}", (new_reserve_0, new_reserve_1));
        // }

        if let Some(pair) = vm.host.evmstate.get_mut(&self.pair_address) {
            pair.insert(EVMU256::from(8), reserve_update(new_reserve_0, new_reserve_1));
        } else {
            let mut pair = HashMap::new();
            pair.insert(EVMU256::from(8), reserve_update(new_reserve_0, new_reserve_1));
            vm.host.evmstate.insert(self.pair_address, pair);
        }

        // 5. now we have raped the pair, setup flashloan data and transfer out
        vm.host
            .evmstate
            .flashloan_data
            .oracle_recheck_balance
            .insert(in_token_address);
        vm.host
            .evmstate
            .flashloan_data
            .oracle_recheck_balance
            .insert(out_token_address);
        vm.host
            .evmstate
            .flashloan_data
            .oracle_recheck_reserve
            .insert(self.pair_address);
        Some((*next, balanceof_token!(false, next) - original_balance))
    }

    fn name(&self) -> String {
        "uniswap_v2".to_string()
    }
}
