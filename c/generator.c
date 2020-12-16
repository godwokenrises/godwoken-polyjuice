/* Layer2 contract generator
 *
 * The generator supposed to be run off-chain.
 * generator dynamic linking with the layer2 contract code,
 * and provides layer2 syscalls.
 *
 * A program should be able to generate a post state after run the generator,
 * and should be able to use the states to construct a transaction that satifies
 * the validator.
 */
#include "ckb_syscalls.h"
#include "common.h"
#include "gw_def.h"
#include "generator.h"
#include "generator/polyjuice.h"

/* syscalls */
#define GW_SYS_STORE 3051
#define GW_SYS_LOAD 3052
#define GW_SYS_SET_RETURN_DATA 3061
#define GW_SYS_CREATE 3071
/* internal syscall only for generator */
#define GW_SYS_LOAD_CALLCONTEXT 4051
#define GW_SYS_LOAD_BLOCKINFO 4052
#define GW_SYS_LOAD_SCRIPT_HASH_BY_ACCOUNT_ID 4053
#define GW_SYS_LOAD_ACCOUNT_ID_BY_SCRIPT_HASH 4054
#define GW_SYS_LOAD_ACCOUNT_SCRIPT 4055

/* 128KB */
#define CALL_CONTEXT_LEN 131072
#define BLOCK_INFO_LEN 128

int main() {
  ckb_debug("BEGIN generator.c");
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
