use std::{
    fs::{self, File},
    path::Path,
    str::FromStr,
    sync::OnceLock,
    time::SystemTime,
};

use handlebars::Handlebars;
use serde::Serialize;
use tracing::{debug, error};

use super::{
    types::{EVMAddress, EVMU256},
    uniswap::{self, UniswapProvider},
    Chain,
    OnChainConfig,
};
use crate::{evm::types::checksum, input::SolutionTx};

/// Template
const TEMPLATE: &str = include_str!("foundry_test.hbs");

/// Cli args.
static CLI_ARGS: OnceLock<CliArgs> = OnceLock::new();

/// Initialize CLI_ARGS.
pub fn init_cli_args(target: String, work_dir: String, onchain: &Option<OnChainConfig>) {
    let (chain, weth, block_number) = match onchain {
        Some(oc) => {
            let weth = get_weth(oc);
            let block_number = oc.block_number.clone();
            let number = EVMU256::from_str_radix(block_number.trim_start_matches("0x"), 16)
                .unwrap()
                .to_string();
            (oc.chain_name.clone(), weth, number)
        }
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
    let trace: Vec<Tx> = inputs.iter().map(Tx::from).collect();
    if trace.is_empty() {
        error!("generate_test error: no trace found.");
        return;
    }
    let args = TemplateArgs::new(solution, trace);
    if args.is_err() {
        debug!("skip generating test: not evm solution.");
        return;
    }
    let args = args.unwrap();
    if fs::create_dir_all(&args.output_dir).is_err() {
        error!(
            "generate_test error: failed to create output dir {:?}.",
            args.output_dir
        );
        return;
    }
    let mut handlebars = Handlebars::new();
    if handlebars.register_template_string("foundry_test", TEMPLATE).is_err() {
        error!("generate_test error: failed to register template file.");
        return;
    }

    let path = format!("{}/{}.t.sol", args.output_dir, args.contract_name);
    let output = File::create(path);
    if output.is_err() {
        error!("generate_test error: failed to create output file.");
        return;
    }

    if let Err(e) = handlebars.render_to_write("foundry_test", &args, &mut output.unwrap()) {
        error!("generate_test error: failed to render template: {:?}", e);
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
    raw_code: String,
    is_deposit: bool,
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
    include_interface: bool,
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

        setup_trace(&mut trace, cli_args);
        let router = get_router(&cli_args.chain);
        let contract_name = make_contract_name(cli_args);
        let include_interface = trace
            .iter()
            .any(|x| !x.raw_code.is_empty() || x.is_borrow || x.liq_percent > 0);

        Ok(Self {
            contract_name,
            is_onchain: cli_args.is_onchain,
            include_interface,
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

fn setup_trace(trace: &mut [Tx], cli_args: &CliArgs) {
    let (mut borrow_idx, mut liq_idx) = (0, 0);
    for tx in trace.iter_mut() {
        // Liquidation
        if tx.liq_percent > 0 {
            tx.liq_idx = liq_idx;
            liq_idx += 1;
        }

        // Raw code
        if let Some(code) = make_raw_code(tx) {
            tx.raw_code = code;
            continue;
        }

        // Borrow
        if tx.is_borrow {
            tx.borrow_idx = borrow_idx;
            borrow_idx += 1;
            // deposit weth
            if tx.contract == cli_args.weth {
                tx.is_deposit = true;
            }
        }

        // ABI Call
        if tx.value == "0" {
            tx.value = "".to_string();
        }
    }
}

fn make_raw_code(tx: &Tx) -> Option<String> {
    if tx.is_borrow || tx.is_deposit {
        return None;
    }

    let code = match tx.fn_signature.as_str() {
        "" => format!("IERC20({}).transfer({}, {});", tx.caller, tx.contract, tx.value),
        "balanceOf(address)" => format!("IERC20({}).balanceOf({});", tx.contract, tx.fn_args),
        "approve(address,uint256)" => format!("IERC20({}).approve({});", tx.contract, tx.fn_args),
        "transfer(address,uint256)" => format!("IERC20({}).transfer({});", tx.contract, tx.fn_args),
        "transferFrom(address,address,uint256)" => {
            format!("IERC20({}).transferFrom({});", tx.contract, tx.fn_args)
        }
        "mint(address)" => format!("IERC20({}).mint({});", tx.contract, tx.fn_args),
        "burn(address)" => format!("IERC20({}).burn({});", tx.contract, tx.fn_args),
        "skim(address)" => format!("IERC20({}).skim({});", tx.contract, tx.fn_args),
        "sync()" => format!("IERC20({}).sync();", tx.contract),
        _ => "".to_string(),
    };

    if code.is_empty() {
        None
    } else {
        Some(code)
    }
}

fn get_router(chain: &str) -> String {
    let chain = Chain::from_str(chain);
    if chain.is_err() {
        return EVMAddress::zero().to_string();
    }
    let chain = chain.unwrap();
    if chain != Chain::ETH && chain != Chain::BSC {
        return EVMAddress::zero().to_string();
    }

    let r = uniswap::get_uniswap_info(&UniswapProvider::UniswapV2, &chain).router;
    checksum(&r)
}

fn make_contract_name(cli_args: &CliArgs) -> String {
    if cli_args.is_onchain {
        return format!("C{}", &cli_args.target[2..6]);
    }

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let default_name = format!("C{}", now);

    Path::new(&cli_args.target)
        .parent()
        .and_then(|parent| parent.file_name())
        .and_then(|dirname| dirname.to_str())
        .map(|dirname| {
            dirname
                .chars()
                .filter(|c| c.is_alphanumeric() || *c == '_')
                .collect::<String>()
        })
        .map(|name| {
            if name.is_empty() {
                default_name.clone()
            } else {
                format!("{}{}", &name[..1].to_uppercase(), &name[1..])
            }
        })
        .unwrap_or(default_name)
}

fn get_weth(oc: &OnChainConfig) -> String {
    let chain = Chain::from_str(&oc.chain_name);
    if chain.is_err() {
        return EVMAddress::zero().to_string();
    }
    let chain = chain.unwrap();
    if chain != Chain::ETH && chain != Chain::BSC {
        return EVMAddress::zero().to_string();
    }

    let weth_str = oc.get_weth(&oc.chain_name);
    checksum(&EVMAddress::from_str(&weth_str).unwrap())
}
