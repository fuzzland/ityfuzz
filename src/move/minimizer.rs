use move_binary_format::CompiledModule;

use super::{
    input::{ConciseMoveInput, MoveFunctionInput},
    types::{MoveAddress, MoveFuzzState, MoveLoc, MoveOutput, MoveSlotTy},
    vm_state::MoveVMState,
};
use crate::{feedback::OracleFeedback, minimizer::SequentialMinimizer, tracer::TxnTrace};

pub struct MoveMinimizer;
use crate::r#move::movevm::MoveVM;
type MoveOracleFeedback<'a> = OracleFeedback<
    'a,
    MoveVMState,
    MoveAddress,
    CompiledModule,
    MoveFunctionInput,
    MoveLoc,
    MoveSlotTy,
    MoveOutput,
    MoveFunctionInput,
    MoveFuzzState,
    ConciseMoveInput,
    MoveVM<MoveFunctionInput, MoveFuzzState>,
>;

impl<E: libafl::executors::HasObservers>
    SequentialMinimizer<MoveFuzzState, E, MoveLoc, MoveAddress, ConciseMoveInput, MoveOracleFeedback<'_>>
    for MoveMinimizer
{
    fn minimize(
        &mut self,
        state: &mut MoveFuzzState,
        _exec: &mut E,
        input: &TxnTrace<MoveLoc, MoveAddress, ConciseMoveInput>,
        _objective: &mut MoveOracleFeedback<'_>,
        _corpus_id: usize,
    ) -> Vec<ConciseMoveInput> {
        input.get_concise_inputs(state)
    }
}
