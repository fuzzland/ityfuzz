mod abi;

use std::{
    collections::{HashMap, HashSet},
    fs::{self, File},
    path::Path,
    sync::OnceLock,
    time::SystemTime,
};

use abi::StructDef;
use handlebars::{handlebars_helper, Handlebars};
use serde::Serialize;
use tracing::{debug, error};

use self::abi::{Abi, DecodedArg};
use super::{types::EVMU256, utils, OnChainConfig};
use crate::{generic_vm::vm_state::SwapInfo, input::SolutionTx};

/// Template
const TEMPLATE: &str = include_str!("foundry_test.hbs");

/// Cli args.
static CLI_ARGS: OnceLock<CliArgs> = OnceLock::new();

// Template helpers to compare strings
handlebars_helper!(is_deposit: |ty: String| ty == "deposit");
handlebars_helper!(is_buy: |ty: String| ty == "buy");
handlebars_helper!(is_withdraw: |ty: String| ty == "withdraw");
handlebars_helper!(is_sell: |ty: String| ty == "sell");

/// Initialize CLI_ARGS.
pub fn init_cli_args(target: String, work_dir: String, onchain: &Option<OnChainConfig>) {
    let (chain, block_number) = match onchain {
        Some(oc) => {
            let block_number = oc.block_number.clone();
            let number = EVMU256::from_str_radix(block_number.trim_start_matches("0x"), 16)
                .unwrap()
                .to_string();
            (oc.chain_name.clone(), number)
        }
        None => (String::from(""), String::from("")),
    };

    let cli_args = CliArgs {
        is_onchain: onchain.is_some(),
        chain,
        target,
        block_number,
        output_dir: format!("{}/vulnerabilities", work_dir),
    };

    let _ = CLI_ARGS.set(cli_args);
}

/// Generate a foundry test file.
pub fn generate_test<T: SolutionTx>(solution: String, inputs: Vec<T>) {
    let solution = utils::remove_color(&solution);

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

    handlebars.register_helper("is_deposit", Box::new(is_deposit));
    handlebars.register_helper("is_buy", Box::new(is_buy));
    handlebars.register_helper("is_withdraw", Box::new(is_withdraw));
    handlebars.register_helper("is_sell", Box::new(is_sell));

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
    output_dir: String,
}

#[derive(Debug, Serialize, Default)]
pub struct Tx {
    interface_calls: Vec<String>,
    // A tx can contain both a `buy` and a `sell` operation at the same time.
    buy_type: BuyType,
    sell_type: SellType,
    borrow_idx: u32,
    caller: String,
    contract: String,
    value: String,
    fn_signature: String,
    fn_selector: String,
    fn_args: String,
    calldata: String,
    liq_percent: u8,
    balance_idx: u32,
    // map<type, swap_info>
    swap_data: HashMap<String, SwapInfo>,
}

impl<T: SolutionTx> From<&T> for Tx {
    fn from(input: &T) -> Self {
        let (is_borrow, mut liq_percent, swap_data) = (input.is_borrow(), input.liq_percent(), input.swap_data());
        let buy_type = BuyType::new(is_borrow, &swap_data);
        let sell_type = SellType::new(liq_percent, &swap_data);

        // Adjust the liq_percent based on whether the `sell` operation is actually
        // executed.
        if liq_percent > 0 && sell_type != SellType::Sell {
            liq_percent = 0;
        }

        Self {
            buy_type,
            sell_type,
            caller: input.caller(),
            contract: input.contract(),
            value: input.value(),
            fn_signature: input.fn_signature(),
            fn_selector: input.fn_selector(),
            fn_args: input.fn_args(),
            calldata: input.calldata(),
            liq_percent,
            swap_data,
            ..Default::default()
        }
    }
}

impl Tx {
    pub fn make_interface_call(&self, args: &[DecodedArg]) -> String {
        let fn_name = self
            .fn_signature
            .split('(')
            .next()
            .unwrap_or(&self.fn_selector)
            .to_string();

        let args = args
            .iter()
            .map(|DecodedArg { value, .. }| value.clone())
            .collect::<Vec<String>>()
            .join(", ");

        let mut fn_call = format!("I({}).{}", self.contract, fn_name);
        if !self.value.is_empty() {
            fn_call.push_str(format!("{{value: {}}}", self.value).as_str());
        }
        fn_call.push_str(format!("({});", args).as_str());
        fn_call
    }
}

#[derive(Debug, Serialize, Default)]
pub struct TemplateArgs {
    contract_name: String,
    // map<struct_signature, struct_def>
    struct_defs: HashMap<String, StructDef>,
    interface: HashSet<String>,
    is_onchain: bool,
    include_interface: bool,
    router: String,
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

        setup_trace(&mut trace);
        let router = get_router(&trace);
        let contract_name = make_contract_name(cli_args);
        let include_interface = trace
            .iter()
            .any(|x| !x.interface_calls.is_empty() || x.buy_type == BuyType::Buy || x.sell_type == SellType::Sell);

        // Decode calldata and collect struct definitions and interface declarations
        let mut struct_defs = HashMap::new();
        let mut interface = HashSet::new();
        for tx in trace.iter_mut() {
            decode_calldata(tx, &mut struct_defs, &mut interface);
        }

        Ok(Self {
            contract_name,
            struct_defs,
            interface,
            is_onchain: cli_args.is_onchain,
            include_interface,
            router,
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

fn decode_calldata(tx: &mut Tx, struct_defs: &mut HashMap<String, StructDef>, interface: &mut HashSet<String>) {
    // Ignore preset interfaces (IERC20 / IUniswapV2Router)
    if !tx.interface_calls.is_empty() || tx.buy_type == BuyType::Buy || tx.sell_type == SellType::Sell {
        return;
    }

    if tx.buy_type == BuyType::Deposit || tx.sell_type == SellType::Withdraw {
        if tx.buy_type == BuyType::Deposit {
            interface.insert("function deposit() external payable;".to_string());
        }
        if tx.sell_type == SellType::Withdraw {
            interface.insert("function withdraw(uint256) external;".to_string());
        }
        return;
    }

    let mut abi = Abi::new();
    if let Ok(args) = abi.decode_input(&tx.fn_signature, &tx.calldata) {
        let sd = abi.take_struct_defs();
        struct_defs.extend(sd.clone());
        interface.insert(make_interface(&tx.fn_signature, &sd));

        tx.interface_calls.extend(abi.take_memory_vars());
        tx.interface_calls.push(tx.make_interface_call(args.as_slice()));
    }
}

fn make_interface(fn_sig: &str, struct_defs: &HashMap<String, StructDef>) -> String {
    let mut fn_decl = fn_sig.to_string();
    // struct_signature: "(address,address,uint24)"
    for (struct_signature, struct_def) in struct_defs.iter() {
        let struct_arr_sig = format!("{}[]", struct_signature);
        if fn_decl.contains(&struct_arr_sig) {
            fn_decl = fn_decl.replace(&struct_arr_sig, &format!("{}[] memory", struct_def.name));
        } else {
            fn_decl = fn_decl.replace(struct_signature, &format!("{} memory", struct_def.name));
        }
    }

    let res = fn_decl
        .replace("bytes,", "bytes memory,")
        .replace("bytes)", "bytes memory)")
        .replace("string,", "string memory,")
        .replace("string)", "string memory)")
        .replace("],", "] memory,")
        .replace("])", "] memory)");

    format!("function {} external payable;", res)
}

fn setup_trace(trace: &mut [Tx]) {
    let (mut borrow_idx, mut balance_idx) = (0, 0);
    for tx in trace.iter_mut() {
        // Liquidation / Withdraw
        if [SellType::Sell, SellType::Withdraw].contains(&tx.sell_type) {
            tx.balance_idx = balance_idx;
            balance_idx += 1;
        }

        // Raw code
        if let Some(call) = make_erc20_calls(tx) {
            tx.interface_calls = vec![call];
            continue;
        }

        // Borrow
        if tx.buy_type == BuyType::Buy {
            tx.borrow_idx = borrow_idx;
            borrow_idx += 1;
        }

        // ABI Call
        if tx.value == "0" {
            tx.value = "".to_string();
        }
    }
}

fn make_erc20_calls(tx: &Tx) -> Option<String> {
    if tx.buy_type != BuyType::None {
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

fn get_router(trace: &[Tx]) -> String {
    trace
        .iter()
        .find(|t| {
            // need swap
            t.buy_type == BuyType::Buy || t.sell_type == SellType::Sell
        })
        .map(|t| {
            if let Some(swap_info) = t.swap_data.get("buy") {
                swap_info.target.clone()
            } else {
                t.swap_data
                    .get("sell")
                    .map(|swap_info| swap_info.target.clone())
                    .unwrap_or_default()
            }
        })
        .unwrap_or_default()
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

#[derive(Clone, Debug, Serialize, Default, PartialEq, Eq)]
#[serde(into = "String")]
pub enum BuyType {
    #[default]
    None,
    Deposit,
    Buy,
}

impl From<BuyType> for String {
    fn from(input: BuyType) -> Self {
        match input {
            BuyType::None => "".to_string(),
            BuyType::Deposit => "deposit".to_string(),
            BuyType::Buy => "buy".to_string(),
        }
    }
}

impl BuyType {
    pub fn new(is_borrow: bool, swap_data: &HashMap<String, SwapInfo>) -> Self {
        if is_borrow {
            if swap_data.contains_key("deposit") {
                return BuyType::Deposit;
            } else if swap_data.contains_key("buy") {
                return BuyType::Buy;
            }
        }
        BuyType::None
    }
}

#[derive(Clone, Debug, Serialize, Default, PartialEq, Eq)]
#[serde(into = "String")]
pub enum SellType {
    #[default]
    None,
    Withdraw,
    Sell,
}

impl From<SellType> for String {
    fn from(input: SellType) -> Self {
        match input {
            SellType::None => "".to_string(),
            SellType::Withdraw => "withdraw".to_string(),
            SellType::Sell => "sell".to_string(),
        }
    }
}

impl SellType {
    pub fn new(liq_percent: u8, swap_data: &HashMap<String, SwapInfo>) -> Self {
        if liq_percent > 0 {
            if swap_data.contains_key("withdraw") {
                return SellType::Withdraw;
            } else if swap_data.contains_key("sell") {
                return SellType::Sell;
            }
        }
        SellType::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockInput {
        caller: String,
        contract: String,
        fn_signature: String,
        fn_selector: String,
        fn_args: String,
        value: String,
        is_borrow: bool,
        liq_percent: u8,
        swap_data: HashMap<String, SwapInfo>,
        calldata: String,
    }

    impl MockInput {
        fn new(fn_sig: &str, calldata: &str, value: &str) -> Self {
            Self {
                caller: String::from(""),
                contract: String::from("0xca143ce32fe78f1f7019d7d551a6402fc5350c73"),
                fn_signature: String::from(fn_sig),
                fn_selector: String::from(""),
                fn_args: String::from(""),
                value: String::from(value),
                is_borrow: false,
                liq_percent: 0,
                swap_data: HashMap::new(),
                calldata: String::from(calldata),
            }
        }
    }

    impl SolutionTx for MockInput {
        fn caller(&self) -> String {
            self.caller.clone()
        }
        fn contract(&self) -> String {
            self.contract.clone()
        }
        fn fn_signature(&self) -> String {
            self.fn_signature.clone()
        }
        fn fn_selector(&self) -> String {
            self.fn_selector.clone()
        }
        fn fn_args(&self) -> String {
            self.fn_args.clone()
        }
        fn value(&self) -> String {
            self.value.clone()
        }
        fn is_borrow(&self) -> bool {
            self.is_borrow
        }
        fn liq_percent(&self) -> u8 {
            self.liq_percent
        }
        fn swap_data(&self) -> HashMap<String, SwapInfo> {
            self.swap_data.clone()
        }
        fn calldata(&self) -> String {
            self.calldata.clone()
        }
    }

    #[test]
    fn test_template_is_valid() {
        let mut handlebars = Handlebars::new();
        assert!(handlebars.register_template_string("foundry_test", TEMPLATE).is_ok());
    }

    #[test]
    fn test_generate_test() {
        let target = "0xca143ce32fe78f1f7019d7d551a6402fc5350c73".to_string();
        let work_dir = "/tmp".to_string();
        init_cli_args(target, work_dir, &None);

        let input1 = MockInput::new(
            "approve(address,uint256)",
            "0x095ea7b300000000000000000000000089257a52ad585aacb1137fcc8abbd03a963b96830000000000000000000000000000000000000000000000056bc75e2d63100000",
            "",
        );
        let input2 = MockInput::new(
            "createPair(address,address)",
            "c9c65396000000000000000000000000aaec620ab3a0aa4e503c544d8715d70082da7891000000000000000000000000bb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
            "1234",
        );
        let inputs = vec![input1, input2];
        let solution = String::from("solution");
        generate_test(solution, inputs);
    }
}
