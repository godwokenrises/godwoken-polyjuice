#include <stdint.h>
#include <stddef.h>

#define GW_GENERATOR
#include "polyjuice.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  // s_INPUT_SIZE = size;
  // dbg_print("s_INPUT_SIZE = %d", s_INPUT_SIZE);


  //TODO: test a simplest contract

  /* Layer 2 contract generator
     *
     * The generator supposed to be run off-chain.
     * generator dynamic linking with the layer2 contract code,
     * and provides layer2 syscalls.
     *
     * A program should be able to generate a post state after run the generator,
     * and should be able to use the states to construct a transaction that satifies
     * the validator.
     */
  if (run_polyjuice() != 0) {
    // TODO: error log
    dbg_print("run_polyjuice failed, input: ...");
    __builtin_trap();
  }
  ckb_debug("=========================== run polyjuice finished ===========================");

  // if (size >= 0)
  //   __builtin_trap();
  return 0;
}
