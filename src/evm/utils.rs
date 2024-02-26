use std::io::Write;

use colored::Colorize;
use regex::Regex;
use revm_primitives::U256;

use crate::input::ConciseSerde;

pub fn colored_address(addr: &str) -> String {
    let (r, g, b) = get_rgb_by_address(addr);
    addr.truecolor(r, g, b).to_string()
}

// The `[Sender]` and the address should be the same color.
pub fn colored_sender(sender: &str) -> String {
    let (r, g, b) = get_rgb_by_address(sender);
    format!("[Sender] {}", sender).truecolor(r, g, b).to_string()
}

pub fn prettify_value(value: U256) -> String {
    if value > U256::from(10).pow(U256::from(15)) {
        let one_eth = U256::from(10).pow(U256::from(18));
        let integer = value / one_eth;
        let decimal: String = (value % one_eth).to_string().chars().take(4).collect();

        format!("{}.{} ether", integer, decimal)
    } else {
        value.to_string()
    }
}

pub fn prettify_concise_inputs<CI: ConciseSerde>(inputs: &[CI]) -> String {
    let mut res = String::new();
    let mut sender = String::new();

    /*
     * The rules for replacing the last `├─` with `└─`:
     * 1. the indentation has reduced
     * 2. the sender has changed in the same layer
     * 3. the last input
     */
    let mut prev_indent_len = 0;
    let mut pending: Option<String> = None;

    for input in inputs {
        // Indentation has reduced.
        if input.indent().len() < prev_indent_len {
            push_last_input(&mut res, pending.take());
        }

        // Sender has changed
        if sender != input.sender() && !input.is_step() {
            // Print the pending input
            if let Some(s) = pending.take() {
                if input.indent().len() == prev_indent_len {
                    push_last_input(&mut res, Some(s)); // └─ call
                } else {
                    res.push_str(format!("{}\n", s).as_str()); // ├─ call
                }
            }

            // Print new sender
            sender = input.sender().clone();
            res.push_str(format!("{}{}\n", input.indent(), colored_sender(&sender)).as_str());
        }

        if let Some(s) = pending.take() {
            res.push_str(format!("{}\n", s).as_str());
        }
        pending = Some(input.serialize_string());
        prev_indent_len = input.indent().len();
    }

    push_last_input(&mut res, pending);
    res
}

pub fn remove_color(input: &str) -> String {
    let reg = Regex::new(r"\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]").unwrap();

    reg.replace_all(input, "").to_string()
}

pub fn try_write_file(path: &str, data: &str, append: bool) -> Result<(), String> {
    let mut retry = 3;
    while retry > 0 {
        retry -= 1;

        match std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(append)
            .open(path)
        {
            Ok(mut file) => match file.write_all(data.as_bytes()) {
                Ok(_) => return Ok(()),
                Err(e) => {
                    if retry <= 0 {
                        return Err(format!("Failed to write to file: {}", e));
                    }
                }
            },
            Err(e) => {
                if retry <= 0 {
                    return Err(format!("Failed to create or open file: {}", e));
                }
            }
        }
    }

    Ok(())
}

fn get_rgb_by_address(addr: &str) -> (u8, u8, u8) {
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

    (rgb[0], rgb[1], rgb[2])
}

fn push_last_input(res: &mut String, input: Option<String>) {
    if input.is_none() {
        return;
    }
    let s = input.unwrap();
    if s.contains("└─") {
        res.push_str(format!("{}\n", s).as_str());
        return;
    }

    let mut parts: Vec<&str> = s.split("├─").collect();
    if let Some(last) = parts.pop() {
        let input = format!("{}└─{}\n", parts.join("├─"), last);
        res.push_str(input.as_str());
    }
}
