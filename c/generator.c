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
#define GW_GENERATOR

#include <stdint.h>
#include "gw_def.h"

/* Call receipt */
typedef struct {
  uint8_t return_data[GW_MAX_RETURN_DATA_SIZE];
  uint32_t return_data_len;
} gw_call_receipt_t;

#include "polyjuice.h"

int main() {
  int ret;

  /* prepare context */
  gw_context_t context;
  ret = gw_context_init(&context);
  if (ret != 0) {
    return ret;
  }

  gw_call_receipt_t receipt;
  receipt.return_data_len = 0;
  /* load layer2 contract */
  ret = handle_message(&context, NULL, &receipt);
  if (ret != 0) {
    return ret;
  }

  ret = context.sys_set_program_return_data(&context,
                                            receipt.return_data,
                                            receipt.return_data_len);
  if (ret != 0) {
    return ret;
  }

  ret = gw_finalize(&context);
  if (ret != 0) {
    return ret;
  }
  return 0;
}
