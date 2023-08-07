use std::collections::{HashMap, HashSet};
use std::fmt::{Debug};
use std::fs::OpenOptions;
use std::io::Write;
use std::ops::AddAssign;
use std::time::{SystemTime, UNIX_EPOCH};
use itertools::Itertools;
use libafl::inputs::Input;
use libafl::prelude::{HasCorpus, HasMetadata, State};
use revm_interpreter::Interpreter;
use revm_interpreter::opcode::{INVALID, JUMPDEST, JUMPI, REVERT, STOP};
use revm_primitives::Bytecode;
use crate::evm::host::FuzzHost;
use crate::evm::input::{ConciseEVMInput, EVMInput, EVMInputT};
use crate::evm::middlewares::middleware::{Middleware, MiddlewareType};
use crate::evm::srcmap::parser::{pretty_print_source_map, SourceMapAvailability, SourceMapLocation};
use crate::evm::srcmap::parser::SourceMapAvailability::Available;
use crate::generic_vm::vm_state::VMStateT;
use crate::input::VMInputT;
use crate::state::{HasCaller, HasCurrentInputIdx, HasItyState};
use crate::evm::types::{EVMAddress, is_zero, ProjectSourceMapTy};
use crate::evm::vm::IN_DEPLOY;


/// Finds all PCs (offsets of bytecode) that are instructions / JUMPDEST
/// Returns a tuple of (instruction PCs, JUMPI PCs, Skip PCs)
pub fn instructions_pc(bytecode: &Bytecode) -> (HashSet<usize>, HashSet<usize>, HashSet<usize>) {
    let mut i = 0;
    let bytes = bytecode.bytes();
    let mut complete_bytes = vec![];
    let mut skip_instructions = HashSet::new();
    let mut total_jumpi_set = HashSet::new();

    while i < bytes.len() {
        let op = *bytes.get(i).unwrap();
        if op == JUMPDEST || op == STOP || op == INVALID {
            skip_instructions.insert(i);
        }
        if op == JUMPI {
            total_jumpi_set.insert(i);
        }
        complete_bytes.push(i);
        i += 1;
        if op >= 0x60 && op <= 0x7f {
            i += op as usize - 0x5f;
        }
    }
    (complete_bytes.into_iter().collect(), total_jumpi_set, skip_instructions)
}


#[derive(Clone, Debug)]
pub struct Coverage {
    pub pc_coverage: HashMap<EVMAddress, HashSet<usize>>,
    pub total_instr: HashMap<EVMAddress, usize>,
    pub total_instr_set: HashMap<EVMAddress, HashSet<usize>>,
    pub total_jumpi_set: HashMap<EVMAddress, HashSet<usize>>,
    pub jumpi_coverage: HashMap<EVMAddress, HashSet<(usize, bool)>>,
    pub skip_pcs: HashMap<EVMAddress, HashSet<usize>>,
    pub work_dir: String,
}


impl Coverage {
    pub fn new() -> Self {
        Self {
            pc_coverage: HashMap::new(),
            total_instr: HashMap::new(),
            total_instr_set: HashMap::new(),
            total_jumpi_set: Default::default(),
            jumpi_coverage: Default::default(),
            skip_pcs: Default::default(),
            work_dir: "work_dir".to_string(),
        }
    }

    pub fn record_instruction_coverage(&mut self, source_map: &ProjectSourceMapTy) {
        // println!("total_instr: {:?}", self.total_instr);
        // println!("total_instr_set: {:?}", self.total_instr_set);
        // println!("pc_coverage: {:?}",  self.pc_coverage);
        let mut detail_cov_report = String::new();

        /// Figure out all instructions to skip
        let mut skip_instructions = HashMap::new();
        let mut pc_info = HashMap::new();
        for (addr, covs) in &self.total_instr_set {
            let mut curr_skip_instructions = self.skip_pcs.get(addr).unwrap_or(&HashSet::new()).clone();

            covs.iter().for_each(|pc| {
                match pretty_print_source_map(*pc, addr, source_map) {
                    SourceMapAvailability::Available(s) => { pc_info.insert((addr, *pc), s); },
                    SourceMapAvailability::Unknown => { curr_skip_instructions.insert(*pc); },
                    SourceMapAvailability::Unavailable => {}
                };
            });
            skip_instructions.insert(*addr, curr_skip_instructions);
        }

        /// Get real total instructions and coverage minus skip instructions
        let mut real_total_instr_set = HashMap::new();
        for (addr, covs) in &self.total_instr_set {
            let mut real_covs = HashSet::new();
            let skips = skip_instructions.get(&addr).unwrap_or(&HashSet::new()).clone();
            for cov in covs {
                if !skips.contains(cov) {
                    real_covs.insert(*cov);
                }
            }
            real_total_instr_set.insert(*addr, real_covs);
        }

        let real_total_jumpi_set = self.total_jumpi_set.iter().map(|(addr, covs)| {
            let mut real_covs = HashSet::new();
            let skips = skip_instructions.get(&addr).unwrap_or(&HashSet::new()).clone();
            for cov in covs {
                if !skips.contains(cov) {
                    real_covs.insert(*cov);
                }
            }
            (*addr, real_covs)
        }).collect::<HashMap<_, _>>();


        let mut real_pc_coverage = HashMap::new();
        for (addr, covs) in &self.pc_coverage {
            let mut real_covs = HashSet::new();
            let skips = skip_instructions.get(&addr).unwrap_or(&HashSet::new()).clone();
            for cov in covs {
                if !skips.contains(cov) {
                    real_covs.insert(*cov);
                }
            }
            real_pc_coverage.insert(*addr, real_covs);
        }

        /// Figure out covered and not covered instructions
        let mut not_covered: HashMap<EVMAddress, HashSet<usize>> = HashMap::new();
        for (addr, covs) in &real_total_instr_set {
            for cov in covs {
                match real_pc_coverage.get_mut(addr) {
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

        detail_cov_report.push_str("\n\nNot Covered Instructions:\n");

        not_covered.iter().for_each(|(addr, pcs)| {
            let mut not_covered_translated = HashSet::new();
            let skips = skip_instructions
                .get(addr)
                .unwrap_or(&HashSet::new())
                .clone();
            pcs.into_iter().for_each(
                |pc| {
                    if !skips.contains(pc) {
                        not_covered_translated
                            .insert(
                                pc_info
                                        .get(&(addr, *pc))
                                        .unwrap_or(&format!("PC: 0x{:x}", pc))
                                        .clone()
                            );
                    }
                }
            );
            if not_covered_translated.len() > 0 {
                detail_cov_report.push_str(&format!(
                    "==================== {:?} ====================\n{}\n\nPC: {:?}\n\n",
                    addr,
                    not_covered_translated.into_iter().sorted().join("\n"),
                    not_covered.get(addr).unwrap_or(&HashSet::new()).iter().sorted().collect_vec()
                ))
            }
        });


        detail_cov_report.push_str("\n\nNot Covered Branches:\n");
        let mut branch_coverage = HashMap::new();

        real_total_jumpi_set.iter().for_each(|(addr, pcs)| {
            let mut cov: HashMap<usize, usize> = HashMap::new();
            pcs.iter().for_each(|pc| { cov.insert(*pc, 0); });

            let total_cov = pcs.len() * 2;
            let empty_set = HashSet::new();
            let existing_cov = self.jumpi_coverage.get(addr)
                .unwrap_or(&empty_set)
                .iter()
                .filter(|(pc, _)| !skip_instructions.get(addr).unwrap_or(&HashSet::new()).contains(pc))
                .collect_vec();

            existing_cov.iter().for_each(|(pc, _)| {
                match cov.get(pc) {
                    Some(v) => { cov.insert(*pc, v + 1); }
                    None => { unreachable!("cov broken") }
                }
            });

            detail_cov_report.push_str(&format!("==================== {:?} ====================\n", addr));
            for (pc, count) in cov {
                if count < 2 {
                    detail_cov_report.push_str(
                        &format!("PC:{:x}, uncovered sides:{}\n{}\n\n",
                                 pc, 2 - count, pc_info.get(&(addr, pc)).unwrap_or(&"".to_string())));
                }
            }
            branch_coverage.insert(*addr, (existing_cov.len(), total_cov));
        });



        let mut data = format!(
            "=================== Coverage Report ===================\n",

        );

        self.total_instr
            .keys()
            .for_each(|k| {
                let cov = real_pc_coverage.get(k).unwrap_or(&Default::default()).len();
                let total = real_total_instr_set.get(k).unwrap_or(&Default::default()).len();
                if total > 2 {
                    data.push_str(format!("Contract: {:?}, Instruction Coverage: {} / {} ({:.2}%)\n",
                            k,
                            cov,
                            total,
                            cov as f64 / total as f64 * 100.0
                    ).as_str());
                }
            });

        self.total_instr
            .keys()
            .for_each(|k| {
                let (cov, total) = branch_coverage.get(k).unwrap_or(&(0, 1));
                if *total > 2 {
                    data.push_str(format!("Contract: {:?}, Branch Coverage: {} / {} ({:.2}%)\n",
                                          k,
                                          *cov,
                                          *total,
                                          *cov as f64 / *total as f64 * 100.0
                    ).as_str());
                }
            });

        println!("\n\n{}", data);

        data.push_str(detail_cov_report.as_str());
        data.push_str("\n\n\n");

        let mut file = OpenOptions::new()
            .write(true)
            .append(false)
            .create(true)
            .open(format!("{}/cov_{}.txt", self.work_dir.clone(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()))
            .unwrap();
        file.write_all(data.as_bytes()).unwrap();
    }
}


impl<I, VS, S> Middleware<VS, I, S> for Coverage
    where
        I: Input + VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT + 'static,
        VS: VMStateT,
        S: State
        + HasCaller<EVMAddress>
        + HasCorpus<I>
        + HasItyState<EVMAddress, EVMAddress, VS, ConciseEVMInput>
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
        if IN_DEPLOY {
            return;
        }
        let address = interp.contract.address;
        let pc = interp.program_counter().clone();
        self.pc_coverage.entry(address).or_default().insert(pc);

        if *interp.instruction_pointer == JUMPI {
            let condition = is_zero(interp.stack.peek(1).unwrap());
            self.jumpi_coverage.entry(address).or_default().insert((pc, condition));
        }
    }

    unsafe fn on_insert(&mut self, bytecode: &mut Bytecode, address: EVMAddress, host: &mut FuzzHost<VS, I, S>, state: &mut S) {
        self.work_dir = host.work_dir.clone();
        let (pcs, jumpis, skip_pcs) = instructions_pc(&bytecode.clone());
        self.total_instr.insert(address, pcs.len());
        self.total_instr_set.insert(address, pcs);
        self.skip_pcs.insert(address, skip_pcs);
        self.total_jumpi_set.insert(address, jumpis);
    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::InstructionCoverage
    }

    unsafe fn on_return(
        &mut self,
        interp: &mut Interpreter,
        host: &mut FuzzHost<VS, I, S>,
        state: &mut S,
    ) {}
}


mod tests {
    use bytes::Bytes;
    use super::*;

    #[test]
    fn test_instructions_pc() {
        let (pcs, _, _) = instructions_pc(&Bytecode::new_raw(
            Bytes::from(
                hex::decode("60806040526004361061004e5760003560e01c80632d2c55651461008d578063819d4cc6146100de5780638980f11f146101005780638b21f170146101205780639342c8f41461015457600080fd5b36610088576040513481527f27f12abfe35860a9a927b465bb3d4a9c23c8428174b83f278fe45ed7b4da26629060200160405180910390a1005b600080fd5b34801561009957600080fd5b506100c17f0000000000000000000000003e40d73eb977dc6a537af587d48316fee66e9c8c81565b6040516001600160a01b0390911681526020015b60405180910390f35b3480156100ea57600080fd5b506100fe6100f93660046106bb565b610182565b005b34801561010c57600080fd5b506100fe61011b3660046106bb565b61024e565b34801561012c57600080fd5b506100c17f000000000000000000000000ae7ab96520de3a18e5e111b5eaab095312d7fe8481565b34801561016057600080fd5b5061017461016f3660046106f3565b610312565b6040519081526020016100d5565b6040518181526001600160a01b0383169033907f6a30e6784464f0d1f4158aa4cb65ae9239b0fa87c7f2c083ee6dde44ba97b5e69060200160405180910390a36040516323b872dd60e01b81523060048201526001600160a01b037f0000000000000000000000003e40d73eb977dc6a537af587d48316fee66e9c8c81166024830152604482018390528316906323b872dd90606401600060405180830381600087803b15801561023257600080fd5b505af1158015610246573d6000803e3d6000fd5b505050505050565b6000811161029a5760405162461bcd60e51b815260206004820152601460248201527316915493d7d49150d3d591549657d05353d5539560621b60448201526064015b60405180910390fd5b6040518181526001600160a01b0383169033907faca8fb252cde442184e5f10e0f2e6e4029e8cd7717cae63559079610702436aa9060200160405180910390a361030e6001600160a01b0383167f0000000000000000000000003e40d73eb977dc6a537af587d48316fee66e9c8c83610418565b5050565b6000336001600160a01b037f000000000000000000000000ae7ab96520de3a18e5e111b5eaab095312d7fe8416146103855760405162461bcd60e51b81526020600482015260166024820152754f4e4c595f4c49444f5f43414e5f574954484452415760501b6044820152606401610291565b478281116103935780610395565b825b91508115610412577f000000000000000000000000ae7ab96520de3a18e5e111b5eaab095312d7fe846001600160a01b0316634ad509b2836040518263ffffffff1660e01b81526004016000604051808303818588803b1580156103f857600080fd5b505af115801561040c573d6000803e3d6000fd5b50505050505b50919050565b604080516001600160a01b038416602482015260448082018490528251808303909101815260649091019091526020810180516001600160e01b031663a9059cbb60e01b17905261046a90849061046f565b505050565b60006104c4826040518060400160405280602081526020017f5361666545524332303a206c6f772d6c6576656c2063616c6c206661696c6564815250856001600160a01b03166105419092919063ffffffff16565b80519091501561046a57808060200190518101906104e2919061070c565b61046a5760405162461bcd60e51b815260206004820152602a60248201527f5361666545524332303a204552433230206f7065726174696f6e20646964206e6044820152691bdd081cdd58d8d9595960b21b6064820152608401610291565b6060610550848460008561055a565b90505b9392505050565b6060824710156105bb5760405162461bcd60e51b815260206004820152602660248201527f416464726573733a20696e73756666696369656e742062616c616e636520666f6044820152651c8818d85b1b60d21b6064820152608401610291565b843b6106095760405162461bcd60e51b815260206004820152601d60248201527f416464726573733a2063616c6c20746f206e6f6e2d636f6e74726163740000006044820152606401610291565b600080866001600160a01b03168587604051610625919061075e565b60006040518083038185875af1925050503d8060008114610662576040519150601f19603f3d011682016040523d82523d6000602084013e610667565b606091505b5091509150610677828286610682565b979650505050505050565b60608315610691575081610553565b8251156106a15782518084602001fd5b8160405162461bcd60e51b8152600401610291919061077a565b600080604083850312156106ce57600080fd5b82356001600160a01b03811681146106e557600080fd5b946020939093013593505050565b60006020828403121561070557600080fd5b5035919050565b60006020828403121561071e57600080fd5b8151801515811461055357600080fd5b60005b83811015610749578181015183820152602001610731565b83811115610758576000848401525b50505050565b6000825161077081846020870161072e565b9190910192915050565b602081526000825180602084015261079981604085016020870161072e565b601f01601f1916919091016040019291505056fea2646970667358221220c0f03149dd58fa21e9bfb72a010b74b1e518d704a2d63d8cc44c0ad3a2f573da64736f6c63430008090033").unwrap()
            )
        ));

        assert_eq!(pcs.len(), 1107);
    }
}
