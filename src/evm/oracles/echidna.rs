use crate::evm::input::EVMInput;
use crate::evm::oracles::erc20::ORACLE_OUTPUT;
use crate::evm::oracles::FUNCTION_BUG_IDX;
use crate::evm::types::{EVMAddress, EVMFuzzState, EVMOracleCtx, EVMU256};
use crate::evm::vm::EVMState;
use crate::oracle::{Oracle, OracleCtx};
use bytes::Bytes;
use revm_primitives::Bytecode;

pub struct EchidnaOracle {
    pub address: EVMAddress,
    echidna_funcs: Vec<Vec<u8>>,
}

impl EchidnaOracle {
    pub fn new(address: EVMAddress, echidna_funcs: Vec<Vec<u8>>) -> Self {
        Self {
            address,
            echidna_funcs,
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
        for echidna_func in self.echidna_funcs.iter() {
            let echidna_txn = Bytes::from(echidna_func.clone());
            let addr = if self.address.is_zero() {
                ctx.input.contract
            } else {
                self.address
            };

            let data = vec![(addr, echidna_txn)];

            let res = ctx.call_post_batch(&data);

            if res.len() == 0 || res[0].len() == 0 {
                continue;
            }

            let res_bool = res
                .iter()
                .map(|out| out.iter().map(|x| *x == 0).all(|x| x))
                .all(|x| x);

            if (res_bool) {
                unsafe {
                    ORACLE_OUTPUT = format!(
                        "[echidna] echidna invariant violated {:?}",
                        ctx.input.contract
                    )
                }
                return vec![FUNCTION_BUG_IDX];
            }
        }

        vec![]
    }
}
