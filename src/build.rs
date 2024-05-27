use std::process::Command;
fn main() {
    // taken from https://stackoverflow.com/questions/43753491/include-git-commit-hash-as-string-into-rust-program
    let output = Command::new("git").args(["rev-parse", "HEAD"]).output().unwrap();
    let git_hash = String::from_utf8(output.stdout).unwrap();

    let features = {
        let mut features = String::new();

        for (k, v) in std::env::vars() {
            if k.starts_with("CARGO_FEATURE_") && v == "1" {
                features.push_str(&format!("{},", &k[14..]));
            }
        }
        features.to_ascii_lowercase()
    };

    println!("cargo:rustc-env=GIT_VERSION_INFO={}[{:?}]", git_hash.trim(), features);
}
