#define __SHARED_LIBRARY__ 1

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "gw_def.h"
#include "common.h"
#include "godwoken.h"
#include "ckb_syscalls.h"

#include <evmc/evmc.h>
#include <evmone/evmone.h>

static char debug_buffer[64 * 1024];
static void debug_print_data(const char *prefix,
                             const uint8_t *data,
                             uint32_t data_len) {
  int offset = 0;
  offset += sprintf(debug_buffer, "%s 0x", prefix);
  for (size_t i = 0; i < data_len; i++) {
    offset += sprintf(debug_buffer + offset, "%02x", data[i]);
  }
  debug_buffer[offset] = '\0';
  ckb_debug(debug_buffer);
}
static void debug_print_int(const char *prefix, int64_t ret) {
  sprintf(debug_buffer, "%s => %ld", prefix, ret);
  ckb_debug(debug_buffer);
}

struct evmc_host_context {};

int init_message(struct evmc_message *msg, gw_context_t* ctx) {
  /* TODO: support CREATE2, DELEGATECALL, CALLCODE */
  if (ctx->call_context.call_type == GW_CALL_TYPE_CONSTRUCT) {
    msg->kind = EVMC_CREATE;
  } else if (ctx->call_context.call_type == GW_CALL_TYPE_HANDLE_MESSAGE) {
    msg->kind = EVMC_CALL;
  } else {
    /* invalid call_type */
    return -1;
  }

  evmc_address sender;
  evmc_address destination;
  ctx->sys_get_address_by_account_id((void *)ctx, ctx->call_context.from_id, sender.bytes);
  ctx->sys_get_address_by_account_id((void *)ctx, ctx->call_context.to_id, destination.bytes);

  /* == Args decoder */
  uint8_t *args = ctx->call_context.args;
  /* args[0..4] */
  uint32_t flags = *((uint32_t *)args);
  /* args[5] */
  uint32_t depth = (uint32_t)args[5];
  /* args[6..38] */
  evmc_uint256be value = *((evmc_uint256be *)(args + 5));
  /* args[38..42] */
  uint32_t input_size = *((uint32_t *)(args + 5 + 32));
  /* args[42..42+input_size] */
  uint8_t *input_data = args + 5 + 32 + 4;

  if (ctx->call_context.args_len != (input_size + 41)) {
    /* ERROR: Invalid args_len */
    return -1;
  }

  msg->flags = flags;
  msg->depth = depth;
  msg->value = value;
  msg->input_data = input_data;
  msg->input_size = input_size;
  msg->gas = 10000000000;
  msg->sender = sender;
  msg->destination = destination;
  msg->create2_salt = evmc_bytes32{};
}

__attribute__((visibility("default"))) int gw_construct(gw_context_t * ctx) {
  return 0;
}

/* parse args then call another contract */
__attribute__((visibility("default"))) int gw_handle_message(gw_context_t* ctx) {
  int ret;
  struct evmc_vm *vm = evmc_create_evmone();
  struct evmc_host_interface interface;
  struct evmc_host_context context;
  struct evmc_message msg;
  ret = init_message(&msg, ctx);
  if (ret != 0) {
    return ret;
  }

  uint8_t *code_data = NULL;
  uint32_t code_size = 0;
  struct evmc_result res = vm->execute(vm, &interface, &context, EVMC_MAX_REVISION, &msg, code_data, code_size);
  return (int)res.status_code;
}
