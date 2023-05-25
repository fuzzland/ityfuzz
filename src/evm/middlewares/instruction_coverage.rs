use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::fs::OpenOptions;
use std::io::Write;
use itertools::Itertools;
use libafl::inputs::Input;
use libafl::prelude::{HasCorpus, HasMetadata, State};
use revm::{Bytecode, Interpreter};
use crate::evm::host::FuzzHost;
use crate::evm::input::EVMInputT;
use crate::evm::middlewares::middleware::{Middleware, MiddlewareType};
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::state::{HasCaller, HasCurrentInputIdx, HasItyState};
use primitive_types::H160;

pub fn instructions_pc(bytecode: &Bytecode) -> HashSet<usize> {
    let mut i = 0;
    let bytes = bytecode.bytes();
    let mut complete_bytes = vec![];

    while i < bytes.len() {
        let op = *bytes.get(i).unwrap();
        complete_bytes.push(i);
        i += 1;
        if op >= 0x60 && op <= 0x7f {
            i += op as usize - 0x5f;
        }
    }
    complete_bytes.into_iter().collect()
}


#[derive(Clone, Debug)]
pub struct InstructionCoverage {
    pub pc_coverage: HashMap<H160, HashSet<usize>>,
    pub total_instr: HashMap<H160, usize>,
    pub total_instr_set: HashMap<H160, HashSet<usize>>,
}


impl InstructionCoverage {
    pub fn new() -> Self {
        Self {
            pc_coverage: HashMap::new(),
            total_instr: HashMap::new(),
            total_instr_set: HashMap::new(),
        }
    }

    pub fn record_instruction_coverage(&mut self) {
        let mut data = format!(
            "coverage: {:?}",
            self.total_instr
                .keys()
                .map(|k| (
                    k,
                    self.pc_coverage.get(k).unwrap_or(&Default::default()).len(),
                    self.total_instr.get(k).unwrap()
                ))
                .collect::<Vec<_>>()
        );

        let mut not_covered: HashMap<H160, HashSet<usize>> = HashMap::new();
        for (addr, covs) in &self.total_instr_set {
            for cov in covs {
                match self.pc_coverage.get_mut(addr) {
                    Some(covs) => {
                        if !covs.contains(cov) {
                            not_covered
                                .entry(*addr)
                                .or_insert(HashSet::new())
                                .insert(*cov);
                        }
                    }
                    None => {
                        not_covered
                            .entry(*addr)
                            .or_insert(HashSet::new())
                            .insert(*cov);
                    }
                }
            }
        }

        data.push_str("\n\n\nnot covered: ");
        not_covered.iter().for_each(|(addr, pcs)| {
            data.push_str(&format!(
                "{:?}: {:?}\n\n",
                addr,
                pcs.into_iter().sorted().collect::<Vec<_>>()
            ));
        });

        let mut file = OpenOptions::new()
            .write(true)
            .append(false)
            .create(true)
            .open("cov.txt")
            .unwrap();
        file.write_all(data.as_bytes()).unwrap();
    }
}


impl<I, VS, S> Middleware<VS, I, S> for InstructionCoverage
    where
        I: Input + VMInputT<VS, H160, H160> + EVMInputT + 'static,
        VS: VMStateT,
        S: State
        + HasCaller<H160>
        + HasCorpus<I>
        + HasItyState<H160, H160, VS>
        + HasMetadata
        + HasCurrentInputIdx
        + Debug
        + Clone,
{
    unsafe fn on_step(
        &mut self,
        interp: &mut Interpreter,
        host: &mut FuzzHost<VS, I, S>,
        state: &mut S,
    ) {
        let address = interp.contract.address;
        let pc = interp.program_counter().clone();
        self.pc_coverage.entry(address).or_default().insert(pc);
    }

    unsafe fn on_insert(&mut self, bytecode: &mut Bytecode, address: H160, host: &mut FuzzHost<VS, I, S>, state: &mut S) {
        let pcs = instructions_pc(&bytecode.clone());
        self.total_instr.insert(address, pcs.len());
        self.total_instr_set.insert(address, pcs);
    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::InstructionCoverage
    }
}