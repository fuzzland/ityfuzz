use colored::Colorize;

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
