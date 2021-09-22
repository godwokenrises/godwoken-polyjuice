/* Layer 2 contract generator
 *
 * The generator supposed to be run off-chain.
 * generator dynamic linking with the layer2 contract code,
 * and provides layer2 syscalls.
 *
 * A program should be able to generate a post state after run the generator,
 * and should be able to use the states to construct a transaction that satisfies
 * the validator.
 */

#define GW_GENERATOR

#include "polyjuice.h"

int main() {
  // A temporal patch to solve https://github.com/nervosnetwork/ckb-vm/issues/97
  CKB_SP_ALIGN;

  int ret = run_polyjuice();

  CKB_SP_ALIGN_END;
  return ret;
}
