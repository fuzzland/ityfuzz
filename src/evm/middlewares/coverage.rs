use std::{
    collections::{HashMap, HashSet},
    fmt::{Debug, Display, Formatter},
    fs,
    fs::OpenOptions,
    io::Write,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use itertools::Itertools;
use libafl::{schedulers::Scheduler, state::HasMetadata};
use revm_interpreter::{
    opcode::{INVALID, JUMPDEST, JUMPI, STOP},
    Interpreter,
};
use revm_primitives::Bytecode;
use serde::Serialize;
use serde_json;
use tracing::info;

use crate::evm::{
    blaz::builder::ArtifactInfoMetadata,
    bytecode_iterator::all_bytecode,
    host::FuzzHost,
    middlewares::middleware::{Middleware, MiddlewareType},
    srcmap::{RawSourceMapInfo, SourceCodeResult, SOURCE_MAP_PROVIDER},
    types::{is_zero, EVMAddress, EVMFuzzState},
    vm::IN_DEPLOY,
};

pub static mut EVAL_COVERAGE: bool = false;

/// Finds all PCs (offsets of bytecode) that are instructions / JUMPDEST
/// Returns a tuple of (instruction PCs, JUMPI PCs, Skip PCs)
pub fn instructions_pc(bytecode: &Bytecode) -> (HashSet<usize>, HashSet<usize>, HashSet<usize>) {
    let mut complete_bytes = vec![];
    let mut skip_instructions = HashSet::new();
    let mut total_jumpi_set = HashSet::new();
    all_bytecode(&bytecode.bytes().to_vec()).iter().for_each(|(pc, op)| {
        if *op == JUMPDEST || *op == STOP || *op == INVALID {
            skip_instructions.insert(*pc);
        }
        if *op == JUMPI {
            total_jumpi_set.insert(*pc);
        }
        complete_bytes.push(*pc);
    });
    (complete_bytes.into_iter().collect(), total_jumpi_set, skip_instructions)
}

#[derive(Clone, Debug)]
pub struct Coverage {
    pub pc_coverage: HashMap<EVMAddress, HashSet<usize>>,
    pub total_instr_set: HashMap<EVMAddress, HashSet<usize>>,
    pub total_jumpi_set: HashMap<EVMAddress, HashSet<usize>>,
    pub jumpi_coverage: HashMap<EVMAddress, HashSet<(usize, bool)>>,
    pub skip_pcs: HashMap<EVMAddress, HashSet<usize>>,
    pub work_dir: String,

    pub address_to_name: HashMap<EVMAddress, String>,
    pub pc_info: HashMap<(EVMAddress, usize), String>, // (address, pc) -> source code

    pub sources: HashMap<EVMAddress, Vec<(String, String)>>, // address -> (filename, content)
}

#[derive(Clone, Debug, Serialize)]
pub struct CoverageResult {
    pub instruction_coverage: usize,
    pub total_instructions: usize,
    pub branch_coverage: usize,
    pub total_branches: usize,
    pub covered_code: Vec<Option<RawSourceMapInfo>>,
    pub address: EVMAddress,
}

impl Default for CoverageResult {
    fn default() -> Self {
        Self::new()
    }
}

impl CoverageResult {
    pub fn new() -> Self {
        Self {
            instruction_coverage: 0,
            total_instructions: 0,
            branch_coverage: 0,
            total_branches: 0,
            covered_code: vec![],
            address: Default::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct SuccintCoverageResult {
    pub instruction_coverage: usize,
    pub total_instructions: usize,
    pub branch_coverage: usize,
    pub total_branches: usize,
    pub address: EVMAddress,
}

#[derive(Clone, Debug, Serialize)]
pub struct CoverageReport {
    pub coverage: HashMap<String, CoverageResult>,
    #[serde(skip)]
    pub files: HashMap<String, Vec<(String, String)>>,
}

impl Default for CoverageReport {
    fn default() -> Self {
        Self::new()
    }
}

impl CoverageReport {
    pub fn new() -> Self {
        Self {
            coverage: HashMap::new(),
            files: Default::default(),
        }
    }

    pub fn succint(&self) -> HashMap<String, SuccintCoverageResult> {
        let mut succint_cov_map = HashMap::new();
        for (contract, cov) in &self.coverage {
            succint_cov_map.insert(
                contract.clone(),
                SuccintCoverageResult {
                    instruction_coverage: cov.instruction_coverage,
                    total_instructions: cov.total_instructions,
                    branch_coverage: cov.branch_coverage,
                    total_branches: cov.total_branches,
                    address: cov.address,
                },
            );
        }
        succint_cov_map
    }

    pub fn dump_file(&self, work_dir: String) {
        // write text file
        let mut text_file = OpenOptions::new()
            .write(true)
            .append(false)
            .create(true)
            .truncate(true)
            .open(format!("{}/coverage.txt", work_dir.clone()))
            .unwrap();
        text_file.write_all(self.to_string().as_bytes()).unwrap();
        text_file.flush().unwrap();

        // write file information
        let mut file_json_file = OpenOptions::new()
            .write(true)
            .append(false)
            .create(true)
            .truncate(true)
            .open(format!("{}/files.json", work_dir))
            .unwrap();
        file_json_file
            .write_all(serde_json::to_string(&self.files).unwrap().as_bytes())
            .unwrap();
        file_json_file.flush().unwrap();

        // write json file
        let mut json_file = OpenOptions::new()
            .write(true)
            .append(false)
            .create(true)
            .truncate(true)
            .open(format!("{}/coverage.json", work_dir))
            .unwrap();
        json_file
            .write_all(serde_json::to_string(self).unwrap().as_bytes())
            .unwrap();
        json_file.flush().unwrap();

        // write succint json file
        let succint_cov_map = self.succint();
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros();
        if !Path::new(&format!("{}/coverage", work_dir)).exists() {
            fs::create_dir_all(format!("{}/coverage", work_dir)).unwrap();
        }
        let mut diff_json_file = OpenOptions::new()
            .write(true)
            .append(false)
            .create(true)
            .truncate(true)
            .open(format!("{}/coverage/cov_{}.json", work_dir, timestamp))
            .unwrap();
        diff_json_file
            .write_all(serde_json::to_string(&succint_cov_map).unwrap().as_bytes())
            .unwrap();
        diff_json_file.flush().unwrap();
    }

    pub fn summarize(&self) {
        info!("============= Coverage Summary =============");
        for (addr, cov) in &self.coverage {
            info!(
                "{}: {:.2}% Instruction Covered, {:.2}% Branch Covered",
                addr,
                (cov.instruction_coverage * 100) as f64 / cov.total_instructions as f64,
                (cov.branch_coverage * 100) as f64 / cov.total_branches as f64
            );
        }
    }
}

impl Display for CoverageReport {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut s = String::new();
        for (addr, cov) in &self.coverage {
            s.push_str(&format!("Contract: {}\n", addr));
            s.push_str(&format!(
                "Instruction Coverage: {}/{} ({:.2}%) \n",
                cov.instruction_coverage,
                cov.total_instructions,
                (cov.instruction_coverage * 100) as f64 / cov.total_instructions as f64
            ));
            s.push_str(&format!(
                "Branch Coverage: {}/{} ({:.2}%) \n",
                cov.branch_coverage,
                cov.total_branches,
                (cov.branch_coverage * 100) as f64 / cov.total_branches as f64
            ));

            // todo: @jacob, dump a html file instead
            s.push_str("--------------------------------\n");
        }
        write!(f, "{}", s)
    }
}

impl Coverage {
    pub fn new(address_to_name: HashMap<EVMAddress, String>, work_dir: String) -> Self {
        Self {
            pc_coverage: HashMap::new(),
            total_instr_set: HashMap::new(),
            total_jumpi_set: Default::default(),
            jumpi_coverage: Default::default(),
            skip_pcs: Default::default(),
            work_dir,
            address_to_name,
            pc_info: Default::default(),
            sources: Default::default(),
        }
    }

    pub fn record_instruction_coverage(&mut self) {
        let mut report = CoverageReport::new();

        // Figure out covered and not covered instructions
        let default_skipper = HashSet::new();

        for (addr, all_pcs) in &self.total_instr_set {
            let name = self.address_to_name.get(addr).unwrap_or(&format!("{:?}", addr)).clone();
            report
                .files
                .insert(name.clone(), self.sources.get(addr).unwrap_or(&vec![]).clone());
            match self.pc_coverage.get_mut(addr) {
                None => {}
                Some(covered) => {
                    let skip_pcs = self.skip_pcs.get(addr).unwrap_or(&default_skipper);
                    // Handle Instruction Coverage
                    let real_covered: HashSet<usize> = covered.difference(skip_pcs).cloned().collect();
                    // let uncovered: Vec<usize> =
                    // all_pcs.difference(&real_covered).cloned().collect_vec();
                    report.coverage.insert(
                        name.clone(),
                        CoverageResult {
                            instruction_coverage: real_covered.len(),
                            total_instructions: all_pcs.len(),
                            branch_coverage: 0,
                            total_branches: 0,
                            covered_code: real_covered
                                .iter()
                                .map(|pc| SOURCE_MAP_PROVIDER.lock().unwrap().get_raw_source_map_info(addr, *pc))
                                .collect(),
                            address: *addr,
                        },
                    );

                    let result_ref = report.coverage.get_mut(&name).unwrap();

                    // Handle Branch Coverage
                    let all_branch_pcs = self.total_jumpi_set.get(addr).unwrap_or(&default_skipper);
                    let empty_set = HashSet::new();
                    let existing_branch_pcs = self
                        .jumpi_coverage
                        .get(addr)
                        .unwrap_or(&empty_set)
                        .iter()
                        .filter(|(pc, _)| !skip_pcs.contains(pc))
                        .collect_vec();
                    result_ref.branch_coverage = existing_branch_pcs.len();
                    result_ref.total_branches = all_branch_pcs.len() * 2;
                }
            }
        }

        // cleanup, remove small contracts
        report.coverage.retain(|_, v| v.total_instructions > 10);
        report.dump_file(self.work_dir.clone());
        report.summarize();
    }
}

impl<SC> Middleware<SC> for Coverage
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    unsafe fn on_step(&mut self, interp: &mut Interpreter, _host: &mut FuzzHost<SC>, _state: &mut EVMFuzzState) {
        if IN_DEPLOY || !EVAL_COVERAGE {
            return;
        }
        let address = interp.contract.code_address;
        let pc = interp.program_counter();
        self.pc_coverage.entry(address).or_default().insert(pc);

        if *interp.instruction_pointer == JUMPI {
            let condition = is_zero(interp.stack.peek(1).unwrap());
            self.jumpi_coverage.entry(address).or_default().insert((pc, condition));
        }
    }

    // This will be called when new bytecode is inserted
    // e.g. meeting a new address/contract
    unsafe fn on_insert(
        &mut self,
        _: Option<&mut Interpreter>,
        _host: &mut FuzzHost<SC>,
        state: &mut EVMFuzzState,
        bytecode: &mut Bytecode,
        address: EVMAddress,
    ) {
        let meta = state
            .metadata_map_mut()
            .get_mut::<ArtifactInfoMetadata>()
            .expect("ArtifactInfoMetadata not found");

        if let Some(build_artifact) = meta.get_mut(&address) {
            self.sources.insert(address, build_artifact.sources.clone());
        }

        let (pcs, jumpis, mut skip_pcs) = instructions_pc(&bytecode.clone());

        // find all skipping PCs
        pcs.iter().for_each(
            |pc| match SOURCE_MAP_PROVIDER.lock().unwrap().get_source_code(&address, *pc) {
                SourceCodeResult::SourceCode(source_code) => {
                    self.pc_info.insert((address, *pc), source_code.clone());
                }
                _ => {
                    skip_pcs.insert(*pc);
                }
            },
        );

        // total instr minus skipped pcs
        let total_instr = pcs.iter().filter(|pc| !skip_pcs.contains(*pc)).cloned().collect();
        self.total_instr_set.insert(address, total_instr);

        // total jumpi minus skipped pcs
        let jumpis = jumpis.iter().filter(|pc| !skip_pcs.contains(*pc)).cloned().collect();
        self.total_jumpi_set.insert(address, jumpis);

        self.skip_pcs.insert(address, skip_pcs);
    }

    fn get_type(&self) -> MiddlewareType {
        MiddlewareType::InstructionCoverage
    }
}

#[cfg(test)]
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
