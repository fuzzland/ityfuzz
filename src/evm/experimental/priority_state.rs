use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::fs::File;
use std::io::Read;
use std::marker::PhantomData;
use libafl::{Error, impl_serdeany};
use libafl::corpus::Corpus;
use libafl::inputs::Input;
use libafl::prelude::{HasMetadata, HasRand, Rand};
use libafl::state::HasCorpus;
use serde::{Deserialize, Serialize};
use crate::evm::contract_utils::set_hash;
use crate::evm::input::EVMInputT;
use crate::evm::types::EVMStagedVMState;
use crate::scheduler::SortedDroppingSchedulerNext;
use crate::state::HasParent;

#[derive(Debug, Serialize, Deserialize)]
pub struct StateScore {
    pub preference: HashMap<[u8; 4], Vec<[u8; 4]>>,
    pub current_sigs: [u8; 4],
    pub state_satisfied: HashMap<usize, Vec<[u8; 4]>>,
}

impl StateScore {
    pub fn new() -> Self {
        Self {
            preference: HashMap::new(),
            current_sigs: [0; 4],
            state_satisfied: HashMap::new(),
        }
    }

    pub fn from_file(path: &str) -> Result<Self, Error> {
        let mut data = String::new();
        let mut scores = StateScore::new();
        File::open(path)?.read_to_string(&mut data)?;
        for line in data.lines() {
            let seq = line.split("@");
            let mut seq_parsed = vec![];
            for sig in seq {
                let mut hash = [0; 4];
                set_hash(sig, &mut hash);
                seq_parsed.push(hash);
            }
            println!("{:?}", seq_parsed);
            for i in 1..seq_parsed.len() {
                let mut pref = vec![];
                for j in 0..i {
                    pref.push(seq_parsed[j]);
                }
                scores.preference.insert(seq_parsed[i], pref);
            }
        }
        println!("{:?}", scores);

        Ok(scores)
    }
}

impl_serdeany!(StateScore);


/// On state added, we push the corresponding index and its preference to list
/// On next, we find the corresponding index and return it
pub struct StateScoreScheulder<InnerSCC> {
    pub _phantom: PhantomData<InnerSCC>,
}

impl<InnerSCC, S> SortedDroppingSchedulerNext<S> for StateScoreScheulder<InnerSCC>
    where     S: HasCorpus<EVMStagedVMState> + HasRand + HasMetadata + HasParent,
              InnerSCC: SortedDroppingSchedulerNext<S>
{
    fn next(state: &mut S) -> Result<usize, Error> {
        // 50% chance to use inner scheduler
        if state.rand_mut().next() % 2 == 0 {
            return InnerSCC::next(state);
        }
        let next = state.rand_mut().next();
        let satisfied = {
            let meta = state.metadata_mut().get_mut::<StateScore>().unwrap();
            let pref = meta.preference.get(&meta.current_sigs).unwrap();
            meta.state_satisfied.iter().filter(|(_, v)| {
                v.ends_with(pref)
            }).map(|(k, _)| k).collect::<Vec<_>>()
        };
        if satisfied.is_empty() {
            return InnerSCC::next(state);
        } else {
            let idx = *satisfied[(next % satisfied.len() as u64) as usize];
            return Ok(idx);
        }
    }

    fn before_on_add(state: &mut S, idx: usize) -> Result<(), Error> {
        let from_idx = state.corpus().get(idx).unwrap().borrow().input().as_ref().unwrap().trace.from_idx;
        let meta = state.metadata_mut().get_mut::<StateScore>().unwrap();
        let sig_trace = if let Some(idx) = from_idx {
            let sig = meta.state_satisfied.get(&idx).unwrap();
            let mut my_sig = sig.clone();
            my_sig.push(meta.current_sigs);
            if my_sig.len() > 4 {
                my_sig.remove(0);
            }

            my_sig
        } else {
            vec![meta.current_sigs]
        };
        meta.state_satisfied.insert(idx, sig_trace);
        Ok(())
    }

    fn before_on_remove(state: &mut S, idx: usize) -> Result<(), Error> {
        let meta = state.metadata_mut().get_mut::<StateScore>().unwrap();
        meta.state_satisfied.remove(&idx).unwrap();
        Ok(())
    }
}

