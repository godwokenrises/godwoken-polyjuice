use criterion::{criterion_group, Criterion};
use gw_common::state::State;
use polyjuice_tests::helper::{
    build_eth_l2_script, deploy, new_account_script, setup, StateExt, CKB_SUDT_ACCOUNT_ID,
};

const SIMPLE_STORAGE_CODE: &str =
    include_str!("../../src/test_cases/evm-contracts/SimpleStorage.bin");
const SIMPLE_WALLET_CODE: &str =
    include_str!("../../src/test_cases/evm-contracts/SimpleWallet.bin");

fn bench(c: &mut Criterion) {
    // TODO: iter_batched
    // fn bench(c: &mut Criterion) {
    //     let data = create_scrambled_data();
    //     c.bench_function("with_setup", move |b| {
    //         // This will avoid timing the to_vec call.
    //         b.iter_batched(|| data.clone(), |mut data| sort(&mut data), BatchSize::SmallInput)
    //     });
    // }

    let (store, mut state, generator, creator_account_id) = setup();

    let block_producer_script = build_eth_l2_script([0x99u8; 20]);
    let block_producer_id = state
        .create_account_from_script(block_producer_script)
        .unwrap();

    let from_script = build_eth_l2_script([1u8; 20]);
    let from_script_hash = from_script.hash();
    let from_short_address = &from_script_hash[0..20];
    let from_id = state.create_account_from_script(from_script).unwrap();
    state
        .mint_sudt(CKB_SUDT_ACCOUNT_ID, from_short_address, 160000000)
        .unwrap();
    let _from_balance1 = state
        .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, from_short_address)
        .unwrap();
    let mut block_number = 0;

    let mut group = c.benchmark_group("Deploy_Contract");
    group.bench_function("SimpleStorage", |b| {
        b.iter(|| {
            block_number += 1;
            // Deploy Contract
            let _run_result = deploy(
                &generator,
                &store,
                &mut state,
                creator_account_id,
                from_id,
                SIMPLE_STORAGE_CODE,
                122000,
                0,
                block_producer_id,
                block_number,
            );
            let account_script = new_account_script(&mut state, creator_account_id, from_id, false);
            let _contract_account_id = state
                .get_account_id_by_script_hash(&account_script.hash().into())
                .unwrap()
                .unwrap();
            // println!(
            //     "[SimpleStorage] contract_account_id: {}",
            //     _contract_account_id
            // );
        })
    });
    group.bench_function("SimpleWallet", |b| {
        b.iter(|| {
            block_number += 1;
            // Deploy Contract
            let _run_result = deploy(
                &generator,
                &store,
                &mut state,
                creator_account_id,
                from_id,
                SIMPLE_WALLET_CODE,
                122000,
                0,
                block_producer_id,
                block_number,
            );
            let account_script = new_account_script(&mut state, creator_account_id, from_id, false);
            let _contract_account_id = state
                .get_account_id_by_script_hash(&account_script.hash().into())
                .unwrap()
                .unwrap();
            // println!(
            //     "[SimpleWallet] contract_account_id: {}",
            //     _contract_account_id
            // );
        })
    });

    // TODO: bench_with_different_contract in a list
    // group.bench_with_input(BenchmarkId::new("Deploy", "SimpleStorage"),
    //     &contract_bin,
    //     |b, i| {
    //     }
    // );

    group.finish();
}

criterion_group! {
    name = bench_deploy_contract;
    config = Criterion::default().sample_size(10);
    targets = bench
}
