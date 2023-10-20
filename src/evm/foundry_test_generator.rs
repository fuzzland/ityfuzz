use std::{fs::File, time::SystemTime};

use handlebars::Handlebars;
use serde::Serialize;

use crate::test_generator::{TestTx, TestGenerator};
use super::{EvmArgs, input::ConciseEVMInput};

const TEMPLATE_PATH: &str = "./foundry_test.hbs";

#[derive(Debug, Serialize, Default)]
pub struct Tx {
    is_borrow: bool,
    caller: String,
    contract: String,
    value: String,
    fn_selector: String,
    fn_args: String,
    liq_percent: u8,
}

impl<T: TestTx> From<&T> for Tx {
    fn from(input: &T) -> Self {
        Self {
            is_borrow: input.is_borrow(),
            caller: input.caller(),
            contract: input.contract(),
            value: input.value(),
            fn_selector: input.fn_selector(),
            fn_args: input.fn_args(),
            liq_percent: input.liq_percent(),
        }
    }
}

#[derive(Debug, Serialize, Default)]
pub struct FoundryTestGenerator {
    target: String,
    chain: String,
    block_number: u64,
    etherscan_keyname: String,
    solution: String,
    trace: Vec<Tx>,
    stepping_with_return: bool,
    output_dir: String,

    #[serde(skip)]
    engine: Handlebars<'static>,
}

impl FoundryTestGenerator {
    pub fn new(args: &EvmArgs) -> Option<Self> {
        let chain = args.chain_type.clone().unwrap_or_default();
        let filename = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut handlebars = Handlebars::new();
        if handlebars.register_template_file("foundry_test", TEMPLATE_PATH).is_err() {
            return None;
        }

        Some(Self {
            target: args.target.clone(),
            chain: chain.clone(),
            block_number: args.onchain_block_number.unwrap_or_default(),
            etherscan_keyname: format!("{}_ETHERSCAN_API_KEY", chain.to_uppercase()),
            output_dir: format!("{}/vulnerabilities/{}.t.sol", args.work_dir, filename),
            engine: handlebars,
            ..Default::default()
        })
    }
}

impl TestGenerator for FoundryTestGenerator {
    type Tx = ConciseEVMInput;

    fn generate_test(&mut self, solution: String, trace: Vec<Self::Tx>) {
        self.solution = solution;
        self.trace = trace.iter().map(|x| Tx::from(x)).collect();
        if self.trace.is_empty() {
            return;
        }

        if self.trace.last().unwrap().fn_selector == "0x00000000" {
            self.trace.pop();
            self.stepping_with_return = true;
        }

        let mut output = File::create(&self.output_dir).unwrap();
        // ignore errors
        let _ = self.engine.render_to_write("foundry_test", &self, &mut output);
    }
}
