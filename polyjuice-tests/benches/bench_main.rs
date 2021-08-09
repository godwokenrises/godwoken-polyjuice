//! Polyjuice Benchmarks main entry.
mod benchmarks;
use criterion::criterion_main;

criterion_main! {
    // TODO
    // benchmarks::polyjuice_generator::pre_compiled_contracts,

    benchmarks::polyjuice_generator::bench_rlp,
    benchmarks::setup::bench_setup,
    benchmarks::deploy_contract::bench_deploy_contract,
}
