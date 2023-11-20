use libafl::schedulers::Scheduler;

use crate::{
    evm::{
        abi::{A256InnerType, BoxedABI, A256},
        input::{ConciseEVMInput, EVMInput, EVMInputT},
        presets::Preset,
        types::{EVMAddress, EVMFuzzState},
        vm::EVMExecutor,
    },
    generic_vm::vm_state::VMStateT,
    input::VMInputT,
};

pub struct PairPreset;

impl<I, VS, SC> Preset<I, VS, SC> for PairPreset
where
    I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT,
    VS: VMStateT,
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    fn presets(
        &self,
        function_sig: [u8; 4],
        input: &EVMInput,
        _evm_executor: &EVMExecutor<VS, ConciseEVMInput, SC>,
    ) -> Vec<EVMInput> {
        let mut res = vec![];
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
                    inner_type: A256InnerType::Address,
                }),
                function: [0xbc, 0x25, 0xcf, 0x77],
            });
            res.push(new_input)
        }
        res
    }
}
