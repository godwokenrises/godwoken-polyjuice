#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "gw_def.h"
#include "common.h"
#include "godwoken.h"
#include "ckb_syscalls.h"

#include <ethash/keccak.hpp>
#include <evmc/evmc.h>
#include <evmone/evmone.h>

/* account script buffer sisze: 32KB */
#define ACCOUNT_SCRIPT_BUFSIZE 32768

static uint8_t polyjuice_script_hash[32] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                            0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,};


bool is_polyjuice_script_hash(const uint8_t script_hash[32]) {
  return memcmp(script_hash, polyjuice_script_hash, 32) == 0;
}

struct evmc_host_context {
  gw_context_t* gw_ctx;
  evmc_address tx_origin;
  int error_code;
};

/**
   Message = [
     depth: u16, (little endian)
     tx_origin: Option<H160>,
     flags: u8,
     value: U256 (big endian),
     input_size: u32, (little endian)
     input_data: [u8],
   ]
 */
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
  uint8_t sender_script_hash[32];
  uint8_t dest_script_hash[32];
  ctx->sys_get_script_hash_by_account_id((void *)ctx, ctx->call_context.from_id, sender_script_hash);
  ctx->sys_get_script_hash_by_account_id((void *)ctx, ctx->call_context.to_id, dest_script_hash);
  memcpy(sender.bytes, sender_script_hash, 20);
  memcpy(destination.bytes, dest_script_hash, 20);

  /* == Args decoder */
  uint8_t *args = ctx->call_context.args;
  size_t tx_origin_len = 0;
  /* args[0..2] */
  uint32_t depth = (uint32_t)(*(uint16_t *)args);
  if (depth > 0) {
    tx_origin_len = 20;
  }
  /* args[2..3] */
  uint8_t flags = *(args + 2 + tx_origin_len);
  /* args[3..35] */
  evmc_uint256be value = *((evmc_uint256be *)(args + 2 + tx_origin_len + 1));
  /* args[35..39] */
  uint32_t input_size = *((uint32_t *)(args + 2 + tx_origin_len + 1 + 32));
  /* args[39..39+input_size] */
  uint8_t *input_data = args + 2 + tx_origin_len + 1 + 32 + 4;

  if (ctx->call_context.args_len != (input_size + 39 + tx_origin_len)) {
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

void release_result(const struct evmc_result* result) {
  free((void *)result->output_data);
  return;
}

int get_account_id_by_address(gw_context_t *ctx, const evmc_address* address, uint32_t *account_id) {
  uint8_t script_hash[32];
  memcpy(script_hash, address->bytes, 20);
  memset(script_hash + 20, 0, 12);
  return ctx->sys_get_account_id_by_script_hash((void *)ctx, script_hash, account_id);
}

int load_account_script(gw_context_t *gw_ctx, uint32_t account_id, uint8_t **code, size_t *code_size) {
  int ret;
  size_t total_size = 0;
  size_t buffer_size = ACCOUNT_SCRIPT_BUFSIZE;
  uint32_t len = (uint32_t) buffer_size;
  uint8_t *buffer = (uint8_t *)malloc(buffer_size);
  size_t offset = 0;
  while (len >= buffer_size) {
    ret = gw_ctx->sys_get_account_script((void *)gw_ctx,
                                         account_id,
                                         &len,
                                         offset,
                                         buffer);
    if (ret != 0) {
      *code = buffer;
      *code_size = total_size;
      return ret;
    }
    total_size += (size_t)len;
    if (len == buffer_size) {
      uint8_t *new_buffer = (uint8_t *)malloc(buffer_size * 2);
      memcpy(new_buffer, buffer, buffer_size);
      len = (uint32_t) buffer_size;
      offset = buffer_size;
      buffer_size *= 2;
      free(buffer);
    }
  }
  *code = buffer;
  *code_size = total_size;
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
  tx_ctx.block_difficulty = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x08, 0xe1, 0xbc, 0x9b, 0xf0, 0x40, 0x00,};
  /* chain id = 1 */
  tx_ctx.chain_id.bytes[31] = 0x01;
  return tx_ctx;
}

bool account_exists(struct evmc_host_context* context,
                    const evmc_address* address) {
  uint32_t account_id;
  int ret = get_account_id_by_address(context->gw_ctx, address, &account_id);
  return ret == 0;
}

evmc_bytes32 get_storage(struct evmc_host_context* context,
                         const evmc_address* address,
                         const evmc_bytes32* key) {
  evmc_bytes32 value{};
  int ret = context->gw_ctx->sys_load((void *)context->gw_ctx,
                                      key->bytes,
                                      (uint8_t *)value.bytes);
  if (ret != 0) {
    context->error_code = ret;
  }
  return value;
}

enum evmc_storage_status set_storage(struct evmc_host_context* context,
                                     const evmc_address* address,
                                     const evmc_bytes32* key,
                                     const evmc_bytes32* value) {
  int ret = context->gw_ctx->sys_store((void *)context->gw_ctx, key->bytes, value->bytes);
  if (ret != 0) {
    context->error_code = ret;
  }
  /* FIXME: more rich evmc_storage_status */
  return EVMC_STORAGE_ADDED;
}

size_t get_code_size(struct evmc_host_context* context,
                     const evmc_address* address) {
  uint32_t account_id = 0;
  int ret = get_account_id_by_address(context->gw_ctx, address, &account_id);
  if (ret != 0) {
    context->error_code = ret;
    return 0;
  }
  uint8_t *code = NULL;
  size_t code_size;
  ret = load_account_script(context->gw_ctx, account_id, &code, &code_size);
  if (ret != 0) {
    context->error_code = ret;
    return 0;
  }
  free((void *)code);
  return code_size;
}

evmc_bytes32 get_code_hash(struct evmc_host_context* context,
                           const evmc_address* address) {
  evmc_bytes32 hash{};
  uint32_t account_id = 0;
  int ret = get_account_id_by_address(context->gw_ctx, address, &account_id);
  if (ret != 0) {
    context->error_code = ret;
    return hash;
  }

  uint8_t *code = NULL;
  size_t code_size;
  ret = load_account_script(context->gw_ctx, account_id, &code, &code_size);
  if (ret != 0) {
    context->error_code = ret;
    return hash;
  }

  union ethash_hash256 hash_result = ethash::keccak256(code, code_size);
  memcpy(hash.bytes, hash_result.bytes, 32);
  free((void *)code);
  return hash;
}

size_t copy_code(struct evmc_host_context* context,
                 const evmc_address* address,
                 size_t code_offset,
                 uint8_t* buffer_data,
                 size_t buffer_size) {

  uint32_t account_id = 0;
  int ret = get_account_id_by_address(context->gw_ctx, address, &account_id);
  if (ret != 0) {
    return (size_t)ret;
  }

  uint32_t len = (uint32_t)buffer_size;
  ret = context->gw_ctx->sys_get_account_script((void *)context->gw_ctx,
                                                    account_id,
                                                    &len,
                                                    code_offset,
                                                    buffer_data);
  if (ret != 0) {
    return ret;
  }
  return 0;
}

evmc_uint256be get_balance(struct evmc_host_context* context,
                           const evmc_address* address) {
  evmc_uint256be balance{};
  uint32_t account_id;
  int ret = get_account_id_by_address(context->gw_ctx, address, &account_id);
  if (ret != 0) {
    return balance;
  }

  /* FIXME */
  return balance;
}

void selfdestruct(struct evmc_host_context* context,
                  const evmc_address* address,
                  const evmc_address* beneficiary) {
  /* FIXME: NOT supported yet! */
  return;
}

struct evmc_result call(struct evmc_host_context* context,
                        const struct evmc_message* msg) {
  int ret;
  struct evmc_result res;

  uint32_t to_id;
  ret = get_account_id_by_address(context->gw_ctx, &(msg->destination), &to_id);
  if (ret != 0) {
    context->error_code = ret;
    res.status_code = EVMC_REVERT;
    return res;
  }

  gw_call_receipt_t receipt;
  uint32_t args_len = (uint32_t)msg->input_size + 39 + 20;
  uint8_t *args = (uint8_t *)malloc(args_len);
  uint8_t flags_u8 = (uint8_t)msg->flags;
  uint16_t depth_u16 = (uint16_t)msg->depth;
  uint32_t input_size_u32 = (uint32_t)msg->input_size;
  memcpy(args, (uint8_t *)(&depth_u16), 2);
  memcpy(args + 2, context->tx_origin.bytes, 20);
  memcpy(args + 2 + 20, &flags_u8, 1);
  memcpy(args + 2 + 20 + 1, msg->value.bytes, 32);
  memcpy(args + 2 + 20 + 1 + 32, (uint8_t *)(&input_size_u32), 4);
  memcpy(args + 2 + 20 + 1 + 32 + 4, msg->input_data, msg->input_size);
  ret = context->gw_ctx->sys_call((void *)context->gw_ctx, to_id, args, args_len, &receipt);
  if (ret != 0) {
    context->error_code = ret;
    res.status_code = EVMC_REVERT;
    return res;
  }

  /* Fill evmc_result */
  res.output_size = (size_t)receipt.return_data_len;
  res.output_data = (uint8_t *)malloc(res.output_size);
  memcpy((void *)res.output_data, receipt.return_data, res.output_size);
  res.release = release_result;
  /* FIXME: res.create_address:
     How to handle create account action?
     ==> Add a API: sys_create(ctx, args, args_len, receipt);
  */

  /* FIXME: handle transfer logic */

  return res;
}

evmc_bytes32 get_block_hash(struct evmc_host_context* context, int64_t number) {
  evmc_bytes32 block_hash{};
  int ret = context->gw_ctx->sys_get_block_hash((void *)context->gw_ctx,
                                                number,
                                                (uint8_t *)block_hash.bytes);
  if (ret != 0) {
    context->error_code = ret;
    return block_hash;
  }
  return block_hash;
}

void emit_log(struct evmc_host_context* context,
              const evmc_address* address,
              const uint8_t* data,
              size_t data_size,
              const evmc_bytes32 topics[],
              size_t topics_count) {
  size_t output_size = 20 + (4 + data_size) + (4 + topics_count * 32);
  uint8_t *output = (uint8_t *)malloc(output_size);
  uint32_t data_size_u32 = (uint32_t)(data_size);
  uint32_t topics_count_u32 = (uint32_t)(topics_count);
  uint8_t *output_current = output;
  memcpy(output_current, address->bytes, 20);
  output_current += 20;
  memcpy(output_current, (uint8_t *)(&data_size_u32), 4);
  output_current += 4;
  memcpy(output_current, data, data_size);
  output_current += data_size;
  memcpy(output_current, (uint8_t *)(&topics_count_u32), 4);
  output_current += 4;
  for (size_t i = 0; i < topics_count; i++) {
    memcpy(output_current, topics[i].bytes, 32);
    output_current += 32;
  }
  int ret = context->gw_ctx->sys_log((void *)context->gw_ctx, (uint32_t) output_size, output);
  if (ret != 0) {
    context->error_code = ret;
  }
  free(output);
  return;
}


/* parse args then create contract */
int gw_construct(gw_context_t * ctx) {
  ckb_debug("BEGIN gw_construct");
  int ret;
  struct evmc_message msg;
  ckb_debug("BEGIN init_message()");
  ret = init_message(&msg, ctx);
  ckb_debug("END init_message()");
  if (ret != 0) {
    return ret;
  }
  if (msg.kind != EVMC_CREATE) {
    /* TODO: Invalid call type or NOT supported yet */
    return -1;
  }

  struct evmc_vm *vm = evmc_create_evmone();
  struct evmc_host_interface interface = { account_exists, get_storage, set_storage, get_balance, get_code_size, get_code_hash, copy_code, selfdestruct, call, get_tx_context, get_block_hash, emit_log};

  evmc_address tx_origin = msg.sender;
  if (msg.depth > 0 ) {
    memcpy(tx_origin.bytes, ctx->call_context.args + 1, 20);
  }
  struct evmc_host_context context { ctx, tx_origin, 0 };

  uint8_t *code_data = NULL;
  size_t code_size = 0;

  ckb_debug("BEGIN vm->execute()");
  struct evmc_result res = vm->execute(vm, &interface, &context, EVMC_MAX_REVISION, &msg, code_data, code_size);
  ckb_debug("END vm->execute()");
  free(code_data);
  if (context.error_code != 0)  {
    return context.error_code;
  }
  /* FIXME: handle created address */

  gw_call_receipt_t *receipt = (gw_call_receipt_t *)ctx->sys_context;
  receipt->return_data_len = (uint32_t)res.output_size;
  memcpy(receipt->return_data, res.output_data, res.output_size);
  ckb_debug("END gw_construct");
  return (int)res.status_code;
}

/* parse args then call contract */
int gw_handle_message(gw_context_t* ctx) {
  int ret;
  struct evmc_message msg;
  ret = init_message(&msg, ctx);
  if (ret != 0) {
    return ret;
  }
  if (msg.kind != EVMC_CALL) {
    /* TODO: Invalid call type or NOT supported yet */
    return -1;
  }

  struct evmc_vm *vm = evmc_create_evmone();
  struct evmc_host_interface interface = { account_exists, get_storage, set_storage, get_balance, get_code_size, get_code_hash, copy_code, selfdestruct, call, get_tx_context, get_block_hash, emit_log};

  evmc_address tx_origin = msg.sender;
  if (msg.depth > 0 ) {
    memcpy(tx_origin.bytes, ctx->call_context.args + 1, 20);
  }
  struct evmc_host_context context { ctx, tx_origin, 0 };

  uint8_t *code_data = NULL;
  size_t code_size = 0;
  ret = load_account_script(ctx, ctx->call_context.to_id, &code_data, &code_size);
  if (ret != 0) {
    return ret;
  }
  struct evmc_result res = vm->execute(vm, &interface, &context, EVMC_MAX_REVISION, &msg, code_data, code_size);
  free(code_data);
  if (context.error_code != 0)  {
    return context.error_code;
  }

  gw_call_receipt_t *receipt = (gw_call_receipt_t *)ctx->sys_context;
  receipt->return_data_len = (uint32_t)res.output_size;
  memcpy(receipt->return_data, res.output_data, res.output_size);
  return (int)res.status_code;
}

int gw_polyjuice_construct(gw_context_t * ctx) {
  return gw_construct(ctx);
}
int gw_polyjuice_handle_message(gw_context_t* ctx) {
  return gw_handle_message(ctx);
}
