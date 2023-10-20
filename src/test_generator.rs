// A test transaction
pub trait TestTx {
    fn is_borrow(&self) -> bool {
        false
    }

    fn caller(&self) -> String {
        String::from("")
    }

    fn contract(&self) -> String {
        String::from("")
    }
    fn value(&self) -> String {
        String::from("")
    }

    fn fn_selector(&self) -> String {
        String::from("")
    }

    fn fn_args(&self) -> String {
        String::from("")
    }

    fn liq_percent(&self) -> u8 {
        0
    }
}

pub trait TestGenerator {
    type Tx: TestTx;

    fn generate_test(&mut self, solution: String, trace: Vec<Self::Tx>) {}
}
