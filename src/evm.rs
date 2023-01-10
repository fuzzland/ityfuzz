use std::{str::FromStr, time::Instant};
use std::borrow::Borrow;
use std::collections::HashMap;
use std::iter::Map;
use std::ops::Deref;

use bytes::Bytes;
use primitive_types::{H160, H256, U256};
use revm::{db::BenchmarkDB, Bytecode, TransactTo, db::CacheDB, Host, Return, Interpreter, Env, SelfDestructResult, Spec, CreateInputs, Gas, CallInputs, LatestSpec, Contract};
use revm::AccountInfo;
use revm::Return::{Continue};
use crate::rand;
const MAP_SIZE: usize = 256;

pub type State = HashMap<H160, HashMap<U256, U256>>;

#[derive(Clone, Debug)]
pub struct FuzzHost {
    env: Env,
    data: State,
    code: HashMap<H160, Bytecode>,
    jmp_map: [u8; MAP_SIZE],
}

impl FuzzHost {
    pub fn new() -> Self {
        Self {
            env: Env::default(),
            data: HashMap::new(),
            code: HashMap::new(),
            jmp_map: [0; MAP_SIZE],
        }
    }

    pub fn set_code(&mut self, address: H160, code: Bytecode) {
        self.code.insert(address, code.to_analysed::<LatestSpec>());
    }
}

impl Host for FuzzHost {
    const INSPECT: bool = false;
    type DB = BenchmarkDB;
    fn step(&mut self, interp: &mut Interpreter, is_static: bool) -> Return {
        unsafe {
            match *interp.instruction_pointer {
                0x57 => {
                    let jump_dest = if interp.stack
                            .peek(0)
                            .expect("stack underflow")
                            .is_zero() {
                        interp.stack.peek(1).expect("stack underflow").as_u64()
                    } else { 1 };
                    self.jmp_map[(
                        interp.program_counter() ^ (jump_dest as usize)
                    ) % MAP_SIZE] += 1;
                }
                _ => {}
            }
        }
        return Continue;
    }

    fn step_end(&mut self, interp: &mut Interpreter, is_static: bool, ret: Return) -> Return {
        return Continue;
    }

    fn env(&mut self) -> &mut Env {
        return &mut self.env;
    }

    fn load_account(&mut self, address: H160) -> Option<(bool, bool)> {
        // todo: exist second param
        unsafe {
            println!("load account {}", address);
        }
        Some((true, self.data.contains_key(&address) || self.code.contains_key(&address)))
    }

    fn block_hash(&mut self, number: U256) -> Option<H256> {
        println!("blockhash {}", number);

        Some(H256::from_str("0x0000000000000000000000000000000000000000000000000000000000000000").unwrap())
    }

    fn balance(&mut self, address: H160) -> Option<(U256, bool)> {
        println!("balance");

        Some((U256::max_value(), true))
    }

    fn code(&mut self, address: H160) -> Option<(Bytecode, bool)> {
        println!("code");
        match self.code.get(&address) {
            Some(code) => Some((code.clone(), true)),
            None => Some((Bytecode::new(), true))
        }
    }

    fn code_hash(&mut self, address: H160) -> Option<(H256, bool)> {
        Some((H256::from_str("0x0000000000000000000000000000000000000000000000000000000000000000").unwrap(), true))
    }

    fn sload(&mut self, address: H160, index: U256) -> Option<(U256, bool)> {
        unsafe {
            println!("sload");
        }
        match self.data.get(&address) {
            Some(account) =>
                Some((account.get(&index).unwrap_or(&U256::zero()).clone(), true)),
            None => Some((U256::zero(), true))
        }
    }

    fn sstore(&mut self, address: H160, index: U256, value: U256) -> Option<(U256, U256, U256, bool)> {
        // unsafe {
        //     // println!("sstore");
        // }
        match self.data.get_mut(&address) {
            Some(account) => account.insert(index, value),
            None => None
        };
        Some((U256::from(0), U256::from(0), U256::from(0), true))
    }

    fn log(&mut self, address: H160, topics: Vec<H256>, data: Bytes) {

    }

    fn selfdestruct(&mut self, address: H160, target: H160) -> Option<SelfDestructResult> {
        return Some(SelfDestructResult::default());
    }

    fn create<SPEC: Spec>(&mut self, inputs: &mut CreateInputs) -> (Return, Option<H160>, Gas, Bytes) {
        unsafe {
            println!("create");
        }
        return (Continue, Some(H160::from_str("0x0000000000000000000000000000000000000000").unwrap()), Gas::new(0), Bytes::new());
    }

    fn call<SPEC: Spec>(&mut self, input: &mut CallInputs) -> (Return, Gas, Bytes) {
        unsafe {
            println!("call");
        }
        return (Continue, Gas::new(0), Bytes::new());
    }
}

#[derive(Debug, Clone)]
pub struct EVMExecutor {
    host: FuzzHost,
    contract_addresses: Vec<H160>,
    deployer: H160,
}

pub struct ExecutionResult {
    pub output: Bytes,
    pub reverted: bool,
    pub new_state: State,
}

impl EVMExecutor {
    pub fn deploy(&mut self, code: Bytecode, constructor_args: Bytes) -> H160 {
        let deployed_address = rand::generate_random_address();
        let deployer = Contract::new::<LatestSpec>(
            constructor_args,
            code,
            deployed_address,
            self.deployer,
            U256::from(0),
        );
        let mut interp = Interpreter::new::<LatestSpec>(deployer, 1e10 as u64);
        let r = interp.run::<FuzzHost, LatestSpec>(&mut self.host);
        assert_eq!(r, Continue);
        self.host.set_code(deployed_address, Bytecode::new_raw(
            interp.return_value()).to_analysed::<LatestSpec>()
        );
        deployed_address
    }

    pub fn execute(&mut self,
                   contract_address: H160,
                   caller: H160,
                   state: &State,
                   data: Bytes) -> ExecutionResult {
        self.host.data = state.clone();
        let call = Contract::new::<LatestSpec>(
            data,
            self.host.code.get(&contract_address).expect("no code").clone(),
            contract_address,
            caller,
            U256::from(0),
        );
        let mut interp = Interpreter::new::<LatestSpec>(call, 1e10 as u64);
        let r = interp.run::<FuzzHost, LatestSpec>(&mut self.host);
        return ExecutionResult {
            output: interp.return_value(),
            reverted: r != Return::Return,
            new_state: self.host.data.clone(),
        };
    }
}
