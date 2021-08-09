use criterion::{criterion_group, Criterion};
use polyjuice_tests::helper;

fn bench(c: &mut Criterion) {
    c.bench_function("setup", |b| b.iter(|| helper::setup()));
}

criterion_group! {
    name = bench_setup;
    config = Criterion::default().sample_size(10);
    targets = bench
}
