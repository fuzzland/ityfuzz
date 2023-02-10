use criterion::{criterion_group, criterion_main, Criterion};
// use crate::abi::get_abi_type_boxed;

fn abi() -> u64 {
    todo!()
}

fn criterion_benchmark(_c: &mut Criterion) {}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
