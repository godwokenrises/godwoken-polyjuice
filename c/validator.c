/* Polyjuice validator */

#define GW_VALIDATOR

/* Layer 1 validator contract
 *
 * Verify:
 *  1. [HOLD] The challenged layer 2 block is belong to the chain
 *  2. [HOLD] The challenged layer 2 transaction is belong to the challenged layer 2 block
 *  3. The kv state changes are valid
 *  4. The entrance account script is valid (lazy, verify when load account script)
 */

#include "ckb_syscalls.h"
#include "gw_smt.h"
#include "gw_syscalls.h"
#include "validator/secp256k1_helper.h"
#include "polyjuice.h"

int main() {
  ckb_debug("BEGIN validator.c");
  int ret;

  /* prepare context */
  gw_context_t context;
  gw_context_init(&context);

  uint32_t old_to_id = context.transaction_context.to_id;
  ret = verify_old_kv_state(&context);
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
  ret = verify_new_kv_state(&context);
  if (ret != 0) {
    return ret;
  }

  debug_print_data("return data",
                   receipt.return_data,
                   receipt.return_data_len);
  debug_print_int("return data length", receipt.return_data_len);
  /* It's a call */
  if (old_to_id == context.transaction_context.to_id) {
    /* Return data from receipt */
    ret = context.sys_set_program_return_data(&context,
                                              receipt.return_data,
                                              receipt.return_data_len);
  }
  if (ret != 0) {
    return ret;
  }

  ckb_debug("END generator.c");
  return 0;
}
