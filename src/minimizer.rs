use std::fmt::Debug;

use serde::{de::DeserializeOwned, Serialize};

use crate::{input::ConciseSerde, tracer::TxnTrace};

pub trait SequentialMinimizer<S, E, Loc, Addr, CI, OF>
where
    CI: Serialize + DeserializeOwned + Debug + Clone + ConciseSerde,
{
    fn minimize(
        &mut self,
        state: &mut S,
        executor: &mut E,
        input: &TxnTrace<Loc, Addr, CI>,
        objective: &mut OF,
        corpus_id: usize,
    ) -> Vec<CI>;
}
