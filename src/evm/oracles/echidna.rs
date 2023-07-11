use crate::evm::input::EVMInput;
use crate::evm::oracles::erc20::ORACLE_OUTPUT;
use crate::evm::oracles::{ECHIDNA_BUG_IDX, FUNCTION_BUG_IDX};
use crate::evm::types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMU256};
use crate::evm::vm::EVMState;
use crate::oracle::{Oracle, OracleCtx};
use bytes::Bytes;
use itertools::Itertools;
use revm_primitives::Bytecode;

pub struct EchidnaOracle {
    pub batch_call_txs: Vec<(EVMAddress, Bytes)>
}

impl EchidnaOracle {
    pub fn new(echidna_funcs: Vec<(EVMAddress, Vec<u8>)>) -> Self {
        Self {
            batch_call_txs: echidna_funcs.iter().map(
                |(address, echidna_func)| {
                    let echidna_txn = Bytes::from(echidna_func.clone());
                    (address.clone(), echidna_txn)
                }
            ).collect_vec()
        }
    }
}

impl
    Oracle<
        EVMState,
        EVMAddress,
        Bytecode,
        Bytes,
        EVMAddress,
        EVMU256,
        Vec<u8>,
        EVMInput,
        EVMFuzzState,
    > for EchidnaOracle
{
    fn transition(&self, ctx: &mut EVMOracleCtx<'_>, stage: u64) -> u64 {
        0
    }

    fn oracle(
        &self,
        ctx: &mut OracleCtx<
            EVMState,
            EVMAddress,
            Bytecode,
            Bytes,
            EVMAddress,
            EVMU256,
            Vec<u8>,
            EVMInput,
            EVMFuzzState,
        >,
        stage: u64,
    ) -> Vec<u64> {
        ctx.call_post_batch(&self.batch_call_txs)
            .iter()
            .map(|out| out.iter().map(|x| *x == 0).all(|x| x))
            .map(|x| if x { ECHIDNA_BUG_IDX } else { 0 })
            .collect_vec()
    }
}
