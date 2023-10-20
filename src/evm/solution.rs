use std::{fs::{File, self}, time::SystemTime, sync::OnceLock};

use handlebars::Handlebars;
use serde::Serialize;

use crate::input::SolutionTx;
use super::EvmArgs;

const TEMPLATE_PATH: &str = "./foundry_test.hbs";
/// Cli args for generating a test command.
static CLI_ARGS: OnceLock<CliArgs> = OnceLock::new();

/// Initialize CLI_ARGS.
pub fn init_cli_args(args: &EvmArgs) {
    let cli_args = CliArgs {
        chain: args.chain_type.clone().unwrap_or_default(),
        target: args.target.clone(),
        block_number: args.onchain_block_number.unwrap_or_default(),
        output_dir: format!("{}/vulnerabilities", args.work_dir),
    };

    let _ = CLI_ARGS.set(cli_args);
}

/// Generate a foundry test file.
pub fn generate_test<T: SolutionTx>(solution: String, inputs: Vec<T>) {
    let mut trace: Vec<Tx> = inputs.iter().map(|x| Tx::from(x)).collect();
    if trace.is_empty() {
        return;
    }
    let args = TemplateArgs::new(solution, trace);
    if args.is_none() {
        return;
    }
    let args = args.unwrap();
    if fs::create_dir_all(&args.output_dir).is_err() {
        return;
    }
    let mut handlebars = Handlebars::new();
    if handlebars.register_template_file("foundry_test", TEMPLATE_PATH).is_err() {
        return;
    }

    let filename = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let path = format!("{}/{}.t.sol", args.output_dir, filename);
    let mut output = File::create(&path).unwrap();
    let _ = handlebars.render_to_write("foundry_test", &args, &mut output);
}


#[derive(Debug, Clone)]
struct CliArgs {
    chain: String,
    target: String,
    block_number: u64,
    output_dir: String,
}

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

impl<T: SolutionTx> From<&T> for Tx {
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
pub struct TemplateArgs {
    target: String,
    chain: String,
    block_number: u64,
    etherscan_keyname: String,
    solution: String,
    trace: Vec<Tx>,
    stepping_with_return: bool,
    output_dir: String,
}

impl TemplateArgs {
    pub fn new(solution: String, mut trace: Vec<Tx>) -> Option<Self> {
        let cli_args = CLI_ARGS.get();
        if cli_args.is_none() {
            return None;
        }
        let cli_args = cli_args.unwrap();

        let mut stepping_with_return = false;
        if trace.last().unwrap().fn_selector == "0x00000000" {
            trace.pop();
            stepping_with_return = true;
        }

        Some(Self {
            target: cli_args.target.clone(),
            chain: cli_args.chain.clone(),
            block_number: cli_args.block_number,
            etherscan_keyname: format!("{}_ETHERSCAN_API_KEY", cli_args.chain.to_uppercase()),
            solution,
            trace,
            stepping_with_return,
            output_dir: cli_args.output_dir.clone(),
        })
    }
}
