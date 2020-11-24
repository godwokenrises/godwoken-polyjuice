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

/* FIXME */
struct evmc_host_context {
  gw_context_t* gw_ctx;
  evmc_address tx_origin;
};

int init_message(struct evmc_message *msg, gw_context_t* ctx) {
  /* TODO: support CREATE2, DELEGATECALL, CALLCODE */
  if (ctx->call_context.call_type == GW_CALL_TYPE_CONSTRUCT) {
    msg->kind = EVMC_CREATE;
  } else if (ctx->call_context.call_type == GW_CALL_TYPE_HANDLE_MESSAGE) {
    msg->kind = EVMC_CALL;
  } else {
    /* ERROR: invalid call_type */
    return -1;
  }

  evmc_address sender;
  evmc_address destination;
  ctx->sys_get_address_by_account_id((void *)ctx, ctx->call_context.from_id, sender.bytes);
  ctx->sys_get_address_by_account_id((void *)ctx, ctx->call_context.to_id, destination.bytes);

  /* == Args decoder */
  uint8_t *args = ctx->call_context.args;
  size_t tx_origin_len = 0;
  /* args[0] */
  uint32_t depth = (uint32_t)args[0];
  if (depth > 0) {
    tx_origin_len = 20;
  }
  /* args[1..5] */
  uint32_t flags = *((uint32_t *)args + 1 + tx_origin_len);
  /* args[5..37] */
  evmc_uint256be value = *((evmc_uint256be *)(args + 1 + tx_origin_len + 4));
  /* args[37..41] */
  uint32_t input_size = *((uint32_t *)(args + 1 + tx_origin_len + 4 + 32));
  /* args[41..41+input_size] */
  uint8_t *input_data = args + 1 + tx_origin_len + 4 + 32 + 4;

  if (ctx->call_context.args_len != (input_size + 41 + tx_origin_len)) {
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
  return 0;
}

////////////////////////////////////////////////////////////////////////////
//// Callbacks
////////////////////////////////////////////////////////////////////////////
struct evmc_tx_context get_tx_context(struct evmc_host_context* context) {
  struct evmc_tx_context tx_ctx{};
  /* gas price = 1 */
  tx_ctx.tx_gas_price.bytes[31] = 0x01;
  tx_ctx.tx_origin = context->tx_origin;
  /* FIXME: get coinbase by aggregator id */
  memset(tx_ctx.block_coinbase.bytes, 0, 20);
  tx_ctx.block_number = context->gw_ctx->block_info.number;
  tx_ctx.block_timestamp = context->gw_ctx->block_info.timestamp;
  tx_ctx.block_gas_limit = 10000000000;
  /* 2500000000000000, TODO: read from aggregator */
  tx_ctx.block_difficulty = {0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00,
                             0x00, 0x08, 0xe1, 0xbc,
                             0x9b, 0xf0, 0x40, 0x00,};
  /* chain id = 1 */
  tx_ctx.chain_id.bytes[31] = 0x01;
  return tx_ctx;
}

bool account_exists(struct evmc_host_context* context,
                    const evmc_address* address) {
  /* FIXME */
  return true;
}

evmc_bytes32 get_storage(struct evmc_host_context* context,
                         const evmc_address* address,
                         const evmc_bytes32* key) {
  evmc_bytes32 value{};
  /* FIXME */
  return value;
}

enum evmc_storage_status set_storage(struct evmc_host_context* context,
                                     const evmc_address* address,
                                     const evmc_bytes32* key,
                                     const evmc_bytes32* value) {
  /* FIXME */
  return EVMC_STORAGE_ADDED;
}

size_t get_code_size(struct evmc_host_context* context,
                     const evmc_address* address) {
  /* FIXME */
  return 0;
}

evmc_bytes32 get_code_hash(struct evmc_host_context* context,
                           const evmc_address* address) {
  evmc_bytes32 hash{};
  /* FIXME */
  return hash;
}

size_t copy_code(struct evmc_host_context* context,
                 const evmc_address* address,
                 size_t code_offset,
                 uint8_t* buffer_data,
                 size_t buffer_size) {
  /* FIXME: */
  return 0;
}

evmc_uint256be get_balance(struct evmc_host_context* context,
                           const evmc_address* address) {
  evmc_uint256be balance{};
  /* FIXME */
  return balance;
}

void selfdestruct(struct evmc_host_context* context,
                  const evmc_address* address,
                  const evmc_address* beneficiary) {
  /* FIXME */
  return;
}

struct evmc_result call(struct evmc_host_context* context,
                        const struct evmc_message* msg) {
  /* FIXME */
  struct evmc_result res;
  return res;
}

evmc_bytes32 get_block_hash(struct evmc_host_context* context, int64_t number) {
  /* FIXME */
  evmc_bytes32 block_hash{};
  return block_hash;
}

void emit_log(struct evmc_host_context* context,
              const evmc_address* address,
              const uint8_t* data,
              size_t data_size,
              const evmc_bytes32 topics[],
              size_t topics_count) {
  /* FIXME */
  return;
}

__attribute__((visibility("default"))) int gw_construct(gw_context_t * ctx) {
  return 0;
}

/* parse args then call another contract */
__attribute__((visibility("default"))) int gw_handle_message(gw_context_t* ctx) {
  int ret;
  struct evmc_vm *vm = evmc_create_evmone();
  struct evmc_host_interface interface = { account_exists, get_storage, set_storage, get_balance, get_code_size, get_code_hash, copy_code, selfdestruct, call, get_tx_context, get_block_hash, emit_log};

  struct evmc_message msg;
  ret = init_message(&msg, ctx);
  if (ret != 0) {
    return ret;
  }
  evmc_address tx_origin = msg.sender;
  if (msg.depth > 0 ) {
    memcpy(tx_origin.bytes, ctx->call_context.args + 1, 20);
  }
  struct evmc_host_context context { ctx, tx_origin };

  uint8_t *code_data = NULL;
  uint32_t code_size = 0;
  struct evmc_result res = vm->execute(vm, &interface, &context, EVMC_MAX_REVISION, &msg, code_data, code_size);
  return (int)res.status_code;
}

