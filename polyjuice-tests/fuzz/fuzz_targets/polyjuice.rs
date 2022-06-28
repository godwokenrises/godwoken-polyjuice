#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate polyjuice_tests;
use polyjuice_tests::ctx::MockChain;

fuzz_target!(|data: &[u8]| {
    let mut chain = MockChain::setup("../..").unwrap();
    let eth_addr = [0u8; 20];
    let from_id = chain
        .create_eoa_account(&eth_addr, 10000000000u64.into())
        .expect("create eoa account");
    let _ = chain.deploy(from_id, data, 5000000, 1, 10000);
});
