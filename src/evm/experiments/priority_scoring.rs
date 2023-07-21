use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::marker::PhantomData;
use libafl::corpus::{Corpus, Testcase};
use libafl::{Error, impl_serdeany};
use libafl::inputs::Input;
use libafl::prelude::{HasMetadata, HasRand, Rand, Scheduler, TestcaseScore};
use libafl::prelude::probabilistic_sampling::ProbabilityMetadata;
use libafl::state::HasCorpus;
use rand::prelude::IteratorRandom;
use crate::evm::input::{EVMInputT, EVMInputTy};
use crate::evm::types::EVMFuzzState;
use serde::Deserialize;
use serde::Serialize;
use crate::evm::contract_utils::set_hash;


#[derive(Debug, Serialize, Deserialize)]
pub struct SigScore {
    pub scores: HashMap<[u8; 4], f64>,
    pub total_score: f64,
    pub sig_indexes: HashMap<[u8; 4], Vec<usize>>
}

impl_serdeany!(SigScore);

impl SigScore {
    pub fn new() -> Self {
        Self {
            scores: HashMap::new(),
            total_score: 0.0,
            sig_indexes: Default::default(),
        }
    }

    pub fn from_file(path: &str) -> Result<Self, Error> {
        let mut data = String::new();
        let mut scores = SigScore::new();
        File::open(path)?.read_to_string(&mut data)?;
        for line in data.lines() {
            let sig = line.split("@").nth(0).unwrap();
            let score = line.split("@").nth(1).unwrap();
            let mut hash = [0; 4];
            set_hash(sig, &mut hash);
            println!("{:?}:{}", hex::encode(hash), 1.0 as f64 / score.parse::<f64>().unwrap());
            scores.register_score(&hash, score.parse::<f64>().unwrap());
        }
        Ok(scores)
    }

    pub fn get_score(&self, sig: &[u8; 4]) -> Option<f64> {
        self.scores.get(sig).copied()
    }

    pub fn register_score(&mut self, sig: &[u8; 4], score: f64) {
        self.scores.insert(*sig, score);
        self.total_score += score;
    }
}




#[derive(Debug, Clone)]
pub struct ProbabilityABISamplingScheduler<I, S>
    where
        I: Input,
        S: HasCorpus<I> + HasMetadata + HasRand,
{
    phantom: PhantomData<(I, S)>,
}

impl<I, S> ProbabilityABISamplingScheduler<I, S>
    where
        I: Input,
        S: HasCorpus<I> + HasMetadata + HasRand,
{
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

impl<I, S> Scheduler<I, S> for ProbabilityABISamplingScheduler<I, S>
    where
        I: Input + EVMInputT,
        S: HasCorpus<I> + HasMetadata + HasRand,
{
    fn on_add(&self, state: &mut S, idx: usize) -> Result<(), Error> {
        let key = match state.corpus().get(idx).unwrap().borrow().input().as_ref().unwrap().get_function() {
            Some(sig) => {
                *sig
            }
            None => {
                [0; 4]
            }
        };
        let meta = state.metadata_mut().get_mut::<SigScore>().unwrap();

        if meta.scores.get(&key).is_none() {
            meta.register_score(&key, 50.0);
        }
        meta.sig_indexes.entry(key).or_insert_with(Vec::new).push(idx);
        Ok(())
    }

    fn next(&self, state: &mut S) -> Result<usize, Error> {
        if state.corpus().count() == 0 {
            Err(Error::empty(String::from("No entries in corpus")))
        } else {
            let sig = {
                let rand_prob: f64 = (state.rand_mut().below(100) as f64) / 100.0;
                let meta = state.metadata().get::<SigScore>().unwrap();
                let threshold = meta.total_score * rand_prob;
                let mut k: f64 = 0.0;
                let mut ret = *meta.scores.keys().last().unwrap();
                for (idx, prob) in meta.scores.iter() {
                    k += prob;
                    if k >= threshold {
                        ret = *idx;
                        break;
                    }
                }
                ret
            };

            let ret = *state.metadata()
                .get::<SigScore>()
                .unwrap()
                .sig_indexes
                .get(&sig)
                .expect("sig not found")
                .iter()
                .next()
                .unwrap();

            *state.corpus_mut().current_mut() = Some(ret);
            Ok(ret)
        }
    }
}
