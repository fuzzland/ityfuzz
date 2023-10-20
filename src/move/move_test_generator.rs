use serde::Serialize;

use crate::test_generator::TestGenerator;
use super::input::ConciseMoveInput;

#[derive(Debug, Serialize, Default)]
pub struct MoveTestGenerator;

impl TestGenerator for MoveTestGenerator {
    type Tx = ConciseMoveInput;
}
