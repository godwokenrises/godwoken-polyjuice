/* Layer 1 validator contract
 *
 * Verify:
 *  1. The kv state changes are valid
 *     - verify old state
 *     - verify new state
 *  2. The entrance account script is valid (lazy, verify when load account
 * script)
 *  3. Verify new accounts
 *  4. Verify return data: hash(return_data) == return_data_hash
 */

#define GW_VALIDATOR

#include "polyjuice.h"

int main() {
  // A temporal patch to solve https://github.com/nervosnetwork/ckb-vm/issues/97
  CKB_SP_ALIGN;

  int ret = run_polyjuice();

  CKB_SP_ALIGN_END;
  return ret;
}
