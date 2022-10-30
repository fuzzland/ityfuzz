use std::path::PathBuf;
use ityfuzz::fuzzers::basic_fuzzer;

fn main() {
    basic_fuzzer::dummyfuzzer(
        PathBuf::from("./tmp/corpus"),
        PathBuf::from("./tmp/objective"),
        PathBuf::from("./tmp/log"),
        &String::from("../demo/*"),
    );
}
