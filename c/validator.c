/* Polyjuice validator */

#define VALIDATOR

/* Layer 1 validator contract
 *
 * Verify:
 *  1. The challenged layer 2 block is belong to the chain
 *  2. The challenged layer 2 transaction is belong to the challenged layer 2 block
 *  3. The kv state changes are valid
 *  4. The entrance account script is valid (lazy verify)
 */

#include "ckb_syscalls.h"
#include "common.h"
#include "gw_def.h"
#include "gw_smt.h"
#include "validator/validator.h"
#include "validator/secp256k1_helper.h"
#include "polyjuice.h"

int main() {
  ckb_debug("BEGIN validator.c");
  int ret;

  /* prepare context */
  gw_verification_context_t context;
  gw_context_init(&context);
  gw_context_t *gw_ctx = &context.gw_ctx;

  uint32_t old_to_id = gw_ctx->transaction_context.to_id;
  /* load layer2 contract */
  ret = handle_message(&context, sizeof(gw_verification_context_t));
  if (ret != 0) {
    return ret;
  }

  debug_print_data("return data",
                   gw_ctx->receipt.return_data,
                   gw_ctx->receipt.return_data_len);
  debug_print_int("return data length", gw_ctx->receipt.return_data_len);
  /* It's a call */
  if (old_to_id == gw_ctx->transaction_context.to_id) {
    /* Return data from receipt */
    ret = gw_ctx->sys_set_program_return_data((void *)(&context),
                                              gw_ctx->receipt.return_data,
                                              gw_ctx->receipt.return_data_len);
  }
  if (ret != 0) {
    return ret;
  }

  ckb_debug("END generator.c");
  return 0;
}
