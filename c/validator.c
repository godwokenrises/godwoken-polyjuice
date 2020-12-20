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
  gw_validator_context_t context;
  gw_context_init(&context);
  gw_context_t *gw_ctx = &context.gw_ctx;

  uint32_t old_to_id = gw_ctx->transaction_context.to_id;
  /* load layer2 contract */
  ret = handle_message(&context, sizeof(gw_validator_context_t));
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
