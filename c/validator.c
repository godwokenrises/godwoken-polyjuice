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

  context.receipt.return_data_len = 0;
  /* load layer2 contract */
  ret = handle_message(&context, NULL, &context.receipt);
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
