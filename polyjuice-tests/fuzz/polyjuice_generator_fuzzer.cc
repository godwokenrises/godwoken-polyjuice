#include <stdint.h>
#include <stddef.h>

#define GW_GENERATOR
/**
 * Layer 2 contract generator
 * The generator supposed to be run off-chain.
 * generator dynamic linking with the layer2 contract code,
 * and provides layer2 syscalls.
 * 
 * A program should be able to generate a post state after run the generator,
 * and should be able to use the states to construct a transaction that satifies
 * the validator.
 */
#include "polyjuice.h"

//TODO: #include MockedGodwoken, including storage, DummyState...
//TODO: construct mock godwoken context => gw_context_init in run_polyjuice()

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  //TODO: in = pupulate_input(data, size)
  // s_INPUT_SIZE = size;
  // dbg_print("s_INPUT_SIZE = %d", s_INPUT_SIZE);

  //TODO: mock syscall(GW_SYS_LOAD_TRANSACTION, ...) <= sysload_l2_transaction(tx_buf, &len) <= 
  // fill the msg into LOAD_TRANSACTION SYSCALL
  // gw_parse_transaction_context -> 

  //TODO: test a simplest contract
  //TODO: wrap run_polyjuice and return the RunResult => struct evmc_result call
  // const auto res = polyjuice_execute();
  if (run_polyjuice() != 0) {
    // TODO: error log
    dbg_print("run_polyjuice failed, input: ...");
    __builtin_trap();
  }
  ckb_debug("=========================== run polyjuice finished ===========================");


  //TODO: check the RunResult


  // temp code
  if (size >= 0)
    __builtin_trap();
  return 0;
}
