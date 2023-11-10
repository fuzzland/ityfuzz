use colored::Colorize;
use revm_primitives::U256;

use crate::input::ConciseSerde;

pub fn colored_address(addr: &str) -> String {
    let default = vec![0x00, 0x76, 0xff];
    // 8 is the length of `0x` + 3 bytes
    let mut rgb = if addr.len() < 8 {
        default.clone()
    } else {
        hex::decode(&addr[addr.len() - 6..]).unwrap_or(default.clone())
    };
    // ignore black and white
    if rgb[..] == [0x00, 0x00, 0x00] || rgb[..] == [0xff, 0xff, 0xff] {
        rgb = default;
    }

    addr.truecolor(rgb[0], rgb[1], rgb[2]).to_string()
}

pub fn pretty_value(value: U256) -> String {
    if value > U256::from(10).pow(U256::from(15)) {
        let one_eth = U256::from(10).pow(U256::from(18));
        let integer = value / one_eth;
        let decimal: String = (value % one_eth).to_string().chars().take(4).collect();

        format!("{}.{} Ether", integer, decimal)
    } else {
        format!("{} Wei", value)
    }
}

pub fn pretty_concise_inputs<CI: ConciseSerde>(inputs: &[CI]) -> String {
    let mut res = String::new();
    let mut sender = String::new();
    for input in inputs {
        // `input.is_step()` indicates that the input is a "stepping with return"
        // and we should not print the sender address.
        if sender != input.sender() && !input.is_step() {
            sender = input.sender().clone();
            res.push_str(
                format!(
                    "{}{} {}\n",
                    input.indent(),
                    "[Sender]".yellow(),
                    colored_address(&sender)
                )
                .as_str(),
            );
        }

        let tx = input.serialize_string();
        if tx.is_empty() {
            continue;
        }
        res.push_str(format!("{}\n", tx).as_str());
    }

    res
}
