use crate::evm::abi::{BoxedABI, A256};
use crate::evm::input::{ConciseEVMInput, EVMInput, EVMInputT};
use crate::evm::presets::presets::Preset;
use crate::evm::types::EVMAddress;
use crate::evm::vm::EVMExecutor;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::state::HasCaller;
use libafl::state::State;
use std::fmt::Debug;

pub struct PairPreset;

impl<I, S, VS> Preset<I, S, VS> for PairPreset
where
    S: State + HasCaller<EVMAddress> + Debug + Clone + 'static,
    I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT,
    VS: VMStateT,
{
    fn presets(
        &self,
        function_sig: [u8; 4],
        input: &EVMInput,
        _evm_executor: &EVMExecutor<I, S, VS, ConciseEVMInput>,
    ) -> Vec<EVMInput> {
        let mut res = vec![];
        // skim(address)
        if let [0xbc, 0x25, 0xcf, 0x77] = function_sig {
            let mut new_input = input.clone();
            let pair = input.get_contract();
            // convert EVMAddress to [u8; 32]
            let mut addr = [0u8; 32];
            addr[12..32].copy_from_slice(pair.0.as_slice());
            new_input.repeat = 37;
            new_input.data = Some(BoxedABI {
                b: Box::new(A256 {
                    data: addr.to_vec(),
                    is_address: true,
                    dont_mutate: true,
                }),
                function: [0xbc, 0x25, 0xcf, 0x77],
            });
            res.push(new_input)
        }
        res
    }
}
