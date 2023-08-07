//! Providing telemetry for the fuzzing campaign

pub use reqwest;
use std::env;
use std::fmt::format;
use serde_json::json;

pub static mut TELEMETRY_ENABLED: bool = true;


const TELEMETRY_HOST: &str = "https://telemetry.fuzz.land/api/v1/";

/// sends a ping to the telemetry server when campaign starts
/// only send (is_onchain, first 10 bytes of contract_address / name)
pub fn report_campaign(is_onchain: bool, contracts: String) {

    if unsafe {TELEMETRY_ENABLED} {
        let json = json!({
            "is_onchain": is_onchain,
            "contracts": contracts
        });
        let client = reqwest::blocking::Client::new();
        client.post(TELEMETRY_HOST.to_owned() + "telemetry").json(&json).send().unwrap();
    }
}

/// sends a ping to the telemetry server when vulnerability is found
pub fn report_vulnerability(vuln: String) {
    if unsafe {TELEMETRY_ENABLED} {
        reqwest::blocking::get(TELEMETRY_HOST.to_owned() + format!("vuln/{}",vuln.len()).as_str())
            .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_report_campaign() {
        report_campaign(true, "0x1234567890".to_string());
    }

    #[test]
    fn test_report_vulnerability() {
        report_vulnerability("reentrancy".to_string());
    }
}
