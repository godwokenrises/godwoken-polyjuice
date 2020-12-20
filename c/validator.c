/* Polyjuice validator */

#define VALIDATOR

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
  gw_context_t context;
  gw_context_init(&context);

  uint32_t old_to_id = context.transaction_context.to_id;
  /* load layer2 contract */
  ret = handle_message(&context);
  if (ret != 0) {
    return ret;
  }

  debug_print_data("return data",
                   context.receipt.return_data,
                   context.receipt.return_data_len);
  debug_print_int("return data length", context.receipt.return_data_len);
  /* It's a call */
  if (old_to_id == context.transaction_context.to_id) {
    /* Return data from receipt */
    ret = context.sys_set_program_return_data((void *)(&context),
                                              context.receipt.return_data,
                                              context.receipt.return_data_len);
  }
  if (ret != 0) {
    return ret;
  }

  ckb_debug("END generator.c");
  return 0;
}
