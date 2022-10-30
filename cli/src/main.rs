use std::path::PathBuf;
use ityfuzz::fuzzers::dummyfuzzer;

fn main() {
    dummyfuzzer::dummyfuzzer(
        PathBuf::from("./tmp/corpus"),
        PathBuf::from("./tmp/objective"),
        PathBuf::from("./tmp/log"),
        &String::from("../demo/*"),
    );
}
