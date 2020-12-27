/* Layer 1 validator contract
 *
 * Verify:
 *  1. The kv state changes are valid
 *     - verify old state
 *     - verify new state
 *  2. The entrance account script is valid (lazy, verify when load account script)
 *  3. Verify new accounts
 *  4. Verify return data: hash(return_data) == return_data_hash
 */
#define GW_VALIDATOR

#include "polyjuice.h"

int main() {
  int ret;



  /* prepare context */
  gw_context_t context;
  ret = gw_context_init(&context);
  if (ret != 0) {
    return ret;
  }

  evmc_message msg;
  uint128_t gas_price;
  /* Parse message */
  ckb_debug("BEGIN parse_message()");
  ret = parse_args(&msg, &gas_price, context->transaction_context);
  ckb_debug("END parse_message()");
  if (ret != 0) {
    return ret;
  }

  context.receipt.return_data_len = 0;
  /* load layer2 contract */
  uint32_t from_id = context->transaction_context.from_id;
  uint32_t to_id = context->transaction_context.to_id;
  ret = handle_message(&context, &msg, from_id, &to_id, &context.receipt);
  if (ret != 0) {
    return ret;
  }

  ret = context.sys_set_program_return_data(&context,
                                            context.receipt.return_data,
                                            context.receipt.return_data_len);
  if (ret != 0) {
    return ret;
  }

  ret = gw_finalize(&context);
  if (ret != 0) {
    return ret;
  }
  return 0;
}
