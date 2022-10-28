use std::fmt::Formatter;
use std::marker::PhantomData;

use libafl::executors::{Executor, ExitKind};
use libafl::inputs::Input;
use libafl::prelude::{HasObservers, ObserversTuple};
use libafl::Error;
use std::fmt::Debug;

use crate::input::VMInputT;
use crate::state::HasExecutionResult;
use crate::EVMExecutor;

#[derive(Clone)]
pub struct FuzzExecutor<I, S, OT>
where
    I: VMInputT,
    OT: ObserversTuple<I, S>,
{
    pub evm_executor: EVMExecutor,
    observers: OT,
    phantom: PhantomData<(I, S)>,
}

impl<I, S, OT> Debug for FuzzExecutor<I, S, OT>
where
    I: VMInputT,
    OT: ObserversTuple<I, S>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FuzzExecutor")
            .field("evm_executor", &self.evm_executor)
            .field("observers", &self.observers)
            .finish()
    }
}

impl<I, S, OT> FuzzExecutor<I, S, OT>
where
    I: VMInputT,
    OT: ObserversTuple<I, S>,
{
    pub fn new(evm_executor: EVMExecutor, observers: OT) -> Self {
        Self {
            evm_executor,
            observers,
            phantom: PhantomData,
        }
    }
}

impl<EM, I, S, Z, OT> Executor<EM, I, S, Z> for FuzzExecutor<I, S, OT>
where
    I: VMInputT + Input,
    OT: ObserversTuple<I, S>,
    S: HasExecutionResult,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        let res = self.evm_executor.execute(
            input.get_contract(),
            input.get_caller(),
            input.get_state(),
            input.to_bytes().clone(),
        );
        // the execution result is added to the fuzzer state
        // later the feedback/objective can run oracle on this result
        state.set_execution_result(res);
        Ok(ExitKind::Ok)
    }
}

// implement HasObservers trait for ItyFuzzer
impl<I, OT, S> HasObservers<I, OT, S> for FuzzExecutor<I, S, OT>
where
    I: VMInputT,
    OT: ObserversTuple<I, S>,
{
    fn observers(&self) -> &OT {
        &self.observers
    }

    fn observers_mut(&mut self) -> &mut OT {
        &mut self.observers
    }
}

mod tests {
    use super::*;
    use crate::abi::get_abi_type;
    use crate::evm::FuzzHost;
    use crate::input::VMInput;
    use crate::rand::generate_random_address;
    use crate::state::FuzzState;
    use crate::state_input::ItyVMState;
    use crate::VMState;
    use bytes::Bytes;
    use libafl::observers::StdMapObserver;
    use libafl::prelude::{tuple_list, HitcountsMapObserver};
    use libafl::state::State;
    use revm::Bytecode;

    #[test]
    fn test_fuzz_executor() {
        let evm_executor = EVMExecutor::new(FuzzHost::new(), vec![], generate_random_address());
        let observers = tuple_list!();
        let mut fuzz_executor: FuzzExecutor<VMInput, FuzzState, ()> =
            FuzzExecutor::new(evm_executor, observers);
        let mut vm_state = VMState::new();

        /*
        contract main {
            function process(uint8 a) public {
                require(a < 2, "2");
            }
        }
        */
        let deployment_bytecode = hex::decode("608060405234801561001057600080fd5b506102ad806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c806390b6e33314610030575b600080fd5b61004a60048036038101906100459190610123565b610060565b60405161005791906101e9565b60405180910390f35b606060028260ff16106100a8576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161009f90610257565b60405180910390fd5b6040518060400160405280600f81526020017f48656c6c6f20436f6e74726163747300000000000000000000000000000000008152509050919050565b600080fd5b600060ff82169050919050565b610100816100ea565b811461010b57600080fd5b50565b60008135905061011d816100f7565b92915050565b600060208284031215610139576101386100e5565b5b60006101478482850161010e565b91505092915050565b600081519050919050565b600082825260208201905092915050565b60005b8381101561018a57808201518184015260208101905061016f565b83811115610199576000848401525b50505050565b6000601f19601f8301169050919050565b60006101bb82610150565b6101c5818561015b565b93506101d581856020860161016c565b6101de8161019f565b840191505092915050565b6000602082019050818103600083015261020381846101b0565b905092915050565b7f3200000000000000000000000000000000000000000000000000000000000000600082015250565b600061024160018361015b565b915061024c8261020b565b602082019050919050565b6000602082019050818103600083015261027081610234565b905091905056fea264697066735822122025c2570c6b62c0201c750ff809bdc45aad0eae99133699dec80912878b9cc33064736f6c634300080f0033").unwrap();

        let deployment_loc = fuzz_executor.evm_executor.deploy(
            Bytecode::new_raw(Bytes::from(deployment_bytecode)),
            Bytes::from(vec![]),
        );

        println!("deployed to address: {:?}", deployment_loc);

        let function_hash = hex::decode("90b6e333").unwrap();

        // process(0)
        let execution_result_0 = fuzz_executor.evm_executor.execute(
            deployment_loc,
            generate_random_address(),
            &vm_state,
            Bytes::from(
                [
                    function_hash.clone(),
                    hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
                        .unwrap(),
                ]
                .concat(),
            ),
        );
        assert_eq!(execution_result_0.reverted, false);

        // process(5)
        let execution_result_5 = fuzz_executor.evm_executor.execute(
            deployment_loc,
            generate_random_address(),
            &vm_state,
            Bytes::from(
                [
                    function_hash.clone(),
                    hex::decode("0000000000000000000000000000000000000000000000000000000000000005")
                        .unwrap(),
                ]
                .concat(),
            ),
        );
        assert_eq!(execution_result_5.reverted, true);
    }
}
