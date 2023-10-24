use std::{fs::{File, self}, sync::OnceLock, path::Path, str::FromStr};

use handlebars::Handlebars;
use serde::Serialize;

use crate::{input::SolutionTx, evm::types::checksum};
use super::{OnChainConfig, Chain, uniswap::{self, UniswapProvider}, types::EVMAddress};

const TEMPLATE_PATH: &str = "./foundry_test.hbs";
/// Cli args for generating a test command.
static CLI_ARGS: OnceLock<CliArgs> = OnceLock::new();

/// Initialize CLI_ARGS.
pub fn init_cli_args(target: String, work_dir: String, onchain: &Option<OnChainConfig>) {
    let (chain, weth, block_number) = match onchain {
        Some(oc) => {
            let weth_str = oc.get_weth(&oc.chain_name);
            let weth = checksum(&EVMAddress::from_str(&weth_str).unwrap());
            (oc.chain_name.clone(), weth, oc.block_number.clone())
        },
        None => (String::from(""), String::from(""), String::from("")),
    };

    let cli_args = CliArgs {
        is_onchain: onchain.is_some(),
        chain,
        target,
        block_number,
        weth,
        output_dir: format!("{}/vulnerabilities", work_dir),
    };

    let _ = CLI_ARGS.set(cli_args);
}

/// Generate a foundry test file.
pub fn generate_test<T: SolutionTx>(solution: String, inputs: Vec<T>) {
    let trace: Vec<Tx> = inputs.iter().map(|x| Tx::from(x)).collect();
    if trace.is_empty() {
        println!("generate_test error: no trace found.");
        return;
    }
    let args = TemplateArgs::new(solution, trace);
    if let Err(e) = args {
        println!("generate_test error: {}", e);
        return;
    }
    let args = args.unwrap();
    if fs::create_dir_all(&args.output_dir).is_err() {
        println!("generate_test error: failed to create output dir {:?}.", args.output_dir);
        return;
    }
    let mut handlebars = Handlebars::new();
    if handlebars.register_template_file("foundry_test", TEMPLATE_PATH).is_err() {
        println!("generate_test error: failed to register template file.");
        return;
    }

    let path = format!("{}/{}.t.sol", args.output_dir, args.contract_name);
    let mut output = File::create(&path).unwrap();
    if let Err(e) = handlebars.render_to_write("foundry_test", &args, &mut output) {
        println!("generate_test error: failed to render template: {:?}", e);
    }
}


#[derive(Debug, Clone)]
struct CliArgs {
    is_onchain: bool,
    chain: String,
    target: String,
    block_number: String,
    weth: String,
    output_dir: String,
}

#[derive(Debug, Serialize, Default)]
pub struct Tx {
    is_transfer: bool,
    is_borrow: bool,
    borrow_idx: u32,
    caller: String,
    contract: String,
    value: String,
    fn_signature: String,
    fn_selector: String,
    fn_args: String,
    liq_percent: u8,
    liq_idx: u32,
}

impl<T: SolutionTx> From<&T> for Tx {
    fn from(input: &T) -> Self {
        Self {
            is_borrow: input.is_borrow(),
            is_transfer: input.is_transfer(),
            caller: input.caller(),
            contract: input.contract(),
            value: input.value(),
            fn_signature: input.fn_signature(),
            fn_selector: input.fn_selector(),
            fn_args: input.fn_args(),
            liq_percent: input.liq_percent(),
            ..Default::default()
        }
    }
}

#[derive(Debug, Serialize, Default)]
pub struct TemplateArgs {
    contract_name: String,
    is_onchain: bool,
    need_swap: bool,
    router: String,
    weth: String,
    chain: String,
    target: String,
    block_number: String,
    etherscan_keyname: String,
    solution: String,
    trace: Vec<Tx>,
    stepping_with_return: bool,
    output_dir: String,
}

impl TemplateArgs {
    pub fn new(solution: String, trace: Vec<Tx>) -> Result<Self, String> {
        let cli_args = CLI_ARGS.get();
        if cli_args.is_none() {
            return Err(String::from("CLI_ARGS is not initialized."));
        }
        let cli_args = cli_args.unwrap();

        // Stepping with return
        let stepping_with_return = trace.iter().any(|tx| tx.fn_selector == "0x00000000");
        let mut trace: Vec<Tx> = trace.into_iter().filter(|tx| tx.fn_selector != "0x00000000").collect();

        let (mut borrow_idx, mut liq_idx) = (0, 0);
        for tx in trace.iter_mut() {
            // Borrow index
            if tx.is_borrow {
                tx.borrow_idx = borrow_idx;
                borrow_idx += 1;
            }
            // Liq index
            if tx.liq_percent > 0 {
                tx.liq_idx = liq_idx;
                liq_idx += 1;
            }
        }

        // Router
        let router = if let Some(chain) = Chain::from_str(&cli_args.chain) {
            let r = uniswap::get_uniswap_info(&UniswapProvider::UniswapV2, &chain).router;
            checksum(&r)
        } else {
            String::from("")
        };

        // Contract name
        let contract_name = if cli_args.is_onchain {
            format!("C{}", &cli_args.target[2..6])
        } else {
            let path = Path::new(&cli_args.target);
            let dirname = path.parent().unwrap().file_name().unwrap().to_str().unwrap();
            let name: String = dirname.chars().filter(|c| c.is_alphanumeric() || *c == '_').collect();
            format!("{}{}", &name[..1].to_uppercase(), &name[1..])
        };

        Ok(Self {
            contract_name,
            is_onchain: cli_args.is_onchain,
            need_swap: trace.iter().any(|x| x.is_borrow || x.liq_percent > 0),
            router,
            weth: cli_args.weth.clone(),
            chain: cli_args.chain.clone(),
            target: cli_args.target.clone(),
            block_number: cli_args.block_number.clone(),
            etherscan_keyname: format!("{}_ETHERSCAN_API_KEY", cli_args.chain.to_uppercase()),
            solution,
            trace,
            stepping_with_return,
            output_dir: cli_args.output_dir.clone(),
        })
    }
}
