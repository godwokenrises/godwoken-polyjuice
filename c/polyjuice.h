#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "gw_def.h"
#include "common.h"
#include "godwoken.h"
#include "sudt_utils.h"
#include "ckb_syscalls.h"

#include <ethash/keccak.hpp>
#include <evmc/evmc.h>
#include <evmc/evmc.hpp>
#include <evmone/evmone.h>
#include "contracts.h"

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

/* account script buffer sisze: 32KB */
#define ACCOUNT_SCRIPT_BUFSIZE 32768
#define GW_ACCOUNT_CONTRACT_CODE 100

static bool script_loaded = false;
static uint32_t sudt_id = UINT32_MAX;
static uint8_t script_code_hash[32];
static uint8_t script_hash_type;

/* FIXME: handle all gas cost */


void gw_build_contract_code_key(uint32_t id, uint8_t key[GW_KEY_BYTES]) {
  gw_build_account_field_key(id, GW_ACCOUNT_CONTRACT_CODE, key);
}

int handle_message(void* ctx, size_t ctx_size);
typedef int (*stream_data_loader_fn)(void *ctx, long data_id,
                                     uint32_t *len, uint32_t offset,
                                     uint8_t *data);

struct evmc_host_context {
  gw_context_t* gw_ctx;
  size_t ctx_size;
  evmc_address tx_origin;
  int error_code;
};

evmc_address account_id_to_address(uint32_t account_id) {
  evmc_address addr;
  memset(addr.bytes, 0, 20);
  memcpy(addr.bytes, (uint8_t *)(&account_id), 4);
  return addr;
}
int address_to_account_id(const evmc_address* address, uint32_t *account_id) {
  for (size_t i = 4; i < 20; i++) {
    if (address->bytes[i] != 0) {
      /* ERROR: invalid polyjuice address */
      return -1;
    }
  }
  *account_id = *((uint32_t *)(address->bytes));
  return 0;
}

// Create a sub context from current context (FIXME: remove this method)
int create_sub_context(const gw_context_t *ctx,
                       gw_context_t *sub_ctx,
                       uint32_t from_id,
                       uint32_t to_id,
                       uint8_t *args,
                       uint32_t args_len) {
  *sub_ctx = *ctx;
  gw_call_receipt_t receipt;
  receipt.return_data_len = 0;
  sub_ctx->receipt = receipt;
  sub_ctx->transaction_context.from_id = from_id;
  sub_ctx->transaction_context.to_id = to_id;
  memcpy(sub_ctx->transaction_context.args, args, args_len);
  sub_ctx->transaction_context.args_len = args_len;
  return 0;
}

/**
   Message = [
     depth      : u16, (little endian)
     tx_origin  : Option<H160>,
     call_kind  : u8
     flags      : u8,
     value      : U256 (big endian),
     input_size : u32, (little endian)
     input_data : [u8],
   ]
 */
int parse_message(struct evmc_message *msg, gw_context_t* ctx) {
  debug_print_int("args_len", ctx->transaction_context.args_len);
  /* == Args decoder */
  size_t offset = 0;
  uint8_t *args = ctx->transaction_context.args;
  /* args[0..2] */
  uint32_t depth = (uint32_t)(*(uint16_t *)args);
  offset += 2;
  debug_print_int("depth", depth);
  if (depth > 0) {
    offset += 20;
  }
  /* args[2..3] */
  evmc_call_kind kind = (evmc_call_kind)*(args + offset);
  offset += 1;
  /* args[3..4] */
  uint8_t flags = *(args + offset);
  offset += 1;
  debug_print_int("flags", flags);
  /* args[4..36] */
  evmc_uint256be value = *((evmc_uint256be *)(args + offset));
  offset += 32;
  debug_print_data("value", value.bytes, 32);
  /* args[36..40] */
  uint32_t input_size = *((uint32_t *)(args + offset));
  offset += 4;
  debug_print_int("input_size", input_size);
  /* args[40..40+input_size] */
  uint8_t *input_data = args + offset;
  debug_print_data("input_data", input_data, input_size);

  if (ctx->transaction_context.args_len != (input_size + offset)) {
    /* ERROR: Invalid args_len */
    return -1;
  }

  /* FIXME: Check from_id and to_id code hash, ONLY ALLOW: [polyjuice, sudt] */
  evmc_address sender = account_id_to_address(ctx->transaction_context.from_id);
  evmc_address destination = account_id_to_address(ctx->transaction_context.to_id);

  msg->kind = kind;
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

int build_script(uint8_t code_hash[32],
                 uint8_t hash_type,
                 uint8_t *args,
                 uint32_t args_len,
                 mol_seg_t *script_seg) {
    /* 1. Build Script by receipt.return_data */
    mol_seg_t args_seg;
    args_seg.size = 4 + args_len;
    args_seg.ptr = (uint8_t *)malloc(4 + args_seg.size);
    memcpy(args_seg.ptr, (uint8_t *)(&args_len), 4);
    memcpy(args_seg.ptr + 4, args, args_len);
    debug_print_data("script.args", args_seg.ptr, args_seg.size);
    debug_print_data("script.code_hash", code_hash, 32);
    debug_print_int("script.hash_type", hash_type);

    mol_builder_t script_builder;
    MolBuilder_Script_init(&script_builder);
    MolBuilder_Script_set_code_hash(&script_builder, code_hash, 32);
    MolBuilder_Script_set_hash_type(&script_builder, hash_type);
    MolBuilder_Script_set_args(&script_builder, args_seg.ptr, args_seg.size);
    mol_seg_res_t script_res = MolBuilder_Script_build(script_builder);
    // Because errno is keyword
    uint8_t error_num = *(uint8_t *)(&script_res);
    if (error_num != MOL_OK) {
      /* ERROR: build script failed */
      return -1;
    }
    *script_seg = script_res.seg;

    debug_print_data("script ", script_seg->ptr, script_seg->size);
    if (MolReader_Script_verify(script_seg, false) != MOL_OK) {
      ckb_debug("built an invalid script");
      return -1;
    }
    return 0;
}

void release_result(const struct evmc_result* result) {
  free((void *)result->output_data);
  return;
}


int load_all_data(gw_context_t *gw_ctx,
                  long data_id,
                  uint8_t **data,
                  size_t *data_size,
                  stream_data_loader_fn loader) {
  int ret;
  size_t total_size = 0;
  size_t buffer_size = ACCOUNT_SCRIPT_BUFSIZE;
  uint32_t len = (uint32_t) buffer_size;
  uint8_t *buffer = (uint8_t *)malloc(buffer_size);
  uint8_t *ptr = buffer;
  size_t offset = 0;
  while (true) {
    ret = loader((void *)gw_ctx, data_id, &len, offset, ptr);
    if (ret != 0) {
      /* ERROR: load account data failed */
      free(buffer);
      *data = NULL;
      *data_size = 0;
      return ret;
    }
    total_size += (size_t)len;
    if (len == buffer_size || len == buffer_size / 2) {
      uint8_t *new_buffer = (uint8_t *)malloc(buffer_size * 2);
      memcpy(new_buffer, buffer, buffer_size);
      free(buffer);
      ptr = new_buffer + total_size;
      buffer = new_buffer;
      offset = buffer_size;
      len = (uint32_t) buffer_size;
      buffer_size *= 2;
    } else {
      break;
    }
  }
  *data = buffer;
  *data_size = total_size;
  debug_print_int("loaded data size", *data_size);
  debug_print_data("loaded data data", *data, *data_size);

  return 0;
}


int data_loader(void *ctx, long data_id,
                uint32_t *len, uint32_t offset,
                uint8_t *data) {
  gw_context_t *gw_ctx = (gw_context_t *)ctx;
  return gw_ctx->sys_load_data(ctx, (uint8_t *)data_id, len, offset, data);
}
int load_account_code(gw_context_t *gw_ctx,
                       uint32_t account_id,
                       uint8_t **code,
                       size_t *code_size) {
  debug_print_int("load_account_code, account_id:", account_id);
  uint8_t key[32];
  uint8_t data_hash[32];
  gw_build_contract_code_key(account_id, key);
  int ret = gw_ctx->sys_load((void *)gw_ctx, account_id, key, data_hash);
  if (ret != 0) {
    return ret;
  }
  return load_all_data(gw_ctx, (long)data_hash, code, code_size, data_loader);
}

int account_script_loader(void *ctx, long data_id,
                          uint32_t *len, uint32_t offset,
                          uint8_t *data) {
  gw_context_t *gw_ctx = (gw_context_t *)ctx;
  return gw_ctx->sys_get_account_script(ctx, (uint32_t)data_id, len, offset, data);
}

int load_account_script(gw_context_t *gw_ctx, uint32_t account_id, mol_seg_t *script_seg) {
  debug_print_int("load_account_script, account_id:", account_id);
  int ret;
  uint8_t *script = NULL;
  size_t script_size = 0;
  ret = load_all_data(gw_ctx, (long)account_id, &script, &script_size, account_script_loader);
  if (ret != 0) {
    return ret;
  }
  script_seg->ptr = script;
  script_seg->size = (uint32_t)script_size;
  if (MolReader_Script_verify(script_seg, false) != MOL_OK) {
    /* ERROR invalid script */
    return -1;
  }
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
  /* TODO: get coinbase by aggregator id */
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
  ckb_debug("BEGIN account_exists");
  uint32_t account_id = 0;
  int ret = address_to_account_id(address, &account_id);
  if (ret != 0) {
    context->error_code = ret;
  }
  ckb_debug("END account_exists");
  return account_id == 0;
}

evmc_bytes32 get_storage(struct evmc_host_context* context,
                         const evmc_address* address,
                         const evmc_bytes32* key) {
  ckb_debug("BEGIN get_storage");
  evmc_bytes32 value{};
  int ret = context->gw_ctx->sys_load((void *)context->gw_ctx,
                                      context->gw_ctx->transaction_context.to_id,
                                      key->bytes,
                                      (uint8_t *)value.bytes);
  if (ret != 0) {
    context->error_code = ret;
  }
  ckb_debug("END get_storage");
  return value;
}

enum evmc_storage_status set_storage(struct evmc_host_context* context,
                                     const evmc_address* address,
                                     const evmc_bytes32* key,
                                     const evmc_bytes32* value) {
  ckb_debug("BEGIN set_storage");
  int ret = context->gw_ctx->sys_store((void *)context->gw_ctx,
                                       context->gw_ctx->transaction_context.to_id,
                                       key->bytes,
                                       value->bytes);
  if (ret != 0) {
    context->error_code = ret;
  }
  /* TODO: more rich evmc_storage_status */
  ckb_debug("END set_storage");
  return EVMC_STORAGE_ADDED;
}

size_t get_code_size(struct evmc_host_context* context,
                     const evmc_address* address) {
  ckb_debug("BEGIN get_code_size");
  uint32_t account_id = 0;
  int ret = address_to_account_id(address, &account_id);
  if (ret != 0) {
    context->error_code = ret;
    return 0;
  }
  uint8_t *code = NULL;
  size_t code_size;
  ret = load_account_code(context->gw_ctx, account_id, &code, &code_size);
  if (ret != 0) {
    context->error_code = ret;
    return 0;
  }
  free(code);
  ckb_debug("END get_code_size");
  return code_size;
}

evmc_bytes32 get_code_hash(struct evmc_host_context* context,
                           const evmc_address* address) {
  ckb_debug("BEGIN get_code_hash");
  evmc_bytes32 hash{};
  uint32_t account_id = 0;
  int ret = address_to_account_id(address, &account_id);
  if (ret != 0) {
    context->error_code = ret;
    return hash;
  }

  uint8_t *code = NULL;
  size_t code_size;
  ret = load_account_code(context->gw_ctx, account_id, &code, &code_size);
  if (ret != 0) {
    context->error_code = ret;
    return hash;
  }

  union ethash_hash256 hash_result = ethash::keccak256(code, code_size);
  memcpy(hash.bytes, hash_result.bytes, 32);
  free(code);
  ckb_debug("END get_code_hash");
  return hash;
}

size_t copy_code(struct evmc_host_context* context,
                 const evmc_address* address,
                 size_t code_offset,
                 uint8_t* buffer_data,
                 size_t buffer_size) {
  ckb_debug("BEGIN copy_code");
  uint32_t account_id = 0;
  int ret = address_to_account_id(address, &account_id);
  if (ret != 0) {
    return (size_t)ret;
  }

  uint32_t len = (uint32_t)buffer_size;
  /* FIXME: change to load_account_code() */
  ret = context->gw_ctx->sys_get_account_script((void *)context->gw_ctx,
                                                    account_id,
                                                    &len,
                                                    code_offset,
                                                    buffer_data);
  if (ret != 0) {
    return ret;
  }
  ckb_debug("END copy_code");
  return 0;
}

evmc_uint256be get_balance(struct evmc_host_context* context,
                           const evmc_address* address) {
  ckb_debug("BEGIN copy_code");
  int ret;
  evmc_uint256be balance{};
  uint32_t account_id;
  ret = address_to_account_id(address, &account_id);
  if (ret != 0) {
    ckb_debug("address to account_id failed");
    context->error_code = -1;
    return balance;
  }

  ckb_debug("END copy_code");
  uint128_t value_u128 = 0;
  ret = sudt_get_balance(context->gw_ctx, sudt_id, account_id, &value_u128);
  if (ret != 0) {
    ckb_debug("sudt_get_balance failed");
    context->error_code = -1;
    return balance;
  }
  uint8_t *value_ptr = (uint8_t *)(&value_u128);
  for (int i = 0; i < 16; i++) {
    balance.bytes[31-i] = *(value_ptr + i);
  }
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
  ckb_debug("BEGIN call");
  int ret;
  struct evmc_result res;
  gw_context_t *gw_ctx = context->gw_ctx;

  /* FIXME: Handle pre-compiled contracts
   *   - check msg->destination
   */
  precompiled_contract_gas_fn contract_gas;
  precompiled_contract_fn contract;
  if (match_precompiled_address(&msg->destination, &contract_gas, &contract)) {
    uint64_t _gas_cost = contract_gas(msg->input_data, msg->input_size);
    ret = contract(gw_ctx,
                   msg->input_data, msg->input_size,
                   (uint8_t **)&res.output_data, &res.output_size);
    if (ret != 0) {
      ckb_debug("call pre-compiled contract failed");
      context->error_code = ret;
      res.status_code = EVMC_REVERT;
      return res;
    }
    res.release = release_result;
    return res;
  }

  uint32_t to_id;
  ret = address_to_account_id(&(msg->destination), &to_id);
  if (ret != 0) {
    ckb_debug("address to account id failed");
    context->error_code = ret;
    res.status_code = EVMC_REVERT;
    return res;
  }

  if (msg->depth > (int32_t)UINT16_MAX) {
    // ERROR: depth too large
    ckb_debug("depth too large");
    context->error_code = -1;
    res.status_code = EVMC_REVERT;
    return res;
  }

  uint32_t args_len = (uint32_t)msg->input_size + 39 + 20;
  uint8_t *args = (uint8_t *)malloc(args_len);
  uint8_t kind_u8 = (uint8_t)msg->kind;
  uint8_t flags_u8 = (uint8_t)msg->flags;
  uint16_t depth_u16 = (uint16_t)msg->depth;
  uint32_t input_size_u32 = (uint32_t)msg->input_size;
  size_t offset = 0;
  memcpy(args + offset, (uint8_t *)(&depth_u16), 2);
  offset += 2;
  memcpy(args + offset, context->tx_origin.bytes, 20);
  offset += 20;
  memcpy(args + offset, &kind_u8, 1);
  offset += 1;
  memcpy(args + offset, &flags_u8, 1);
  offset += 1;
  memcpy(args + offset, msg->value.bytes, 32);
  offset += 32;
  memcpy(args + offset, (uint8_t *)(&input_size_u32), 4);
  offset += 4;
  memcpy(args + offset, msg->input_data, msg->input_size);

  /* prepare context */
  uint32_t from_id = gw_ctx->transaction_context.to_id;
  void *sub_ctx = malloc(context->ctx_size);
  memcpy(sub_ctx, context->gw_ctx, context->ctx_size);
  gw_context_t *sub_gw_ctx = (gw_context_t *)sub_ctx;
  ret = create_sub_context(gw_ctx, sub_gw_ctx, from_id, to_id, args, args_len);
  if (ret != 0) {
    ckb_debug("create sub context failed");
    context->error_code = ret;
    res.status_code = EVMC_REVERT;
    return res;
  }
  gw_call_receipt_t *receipt = &sub_gw_ctx->receipt;

  /* TODO: handle special kind (CREATE2/CALLCODE/DELEGATECALL)*/
  ret = handle_message(sub_gw_ctx, context->ctx_size);
  if (ret != 0) {
    ckb_debug("inner call failed (transfer/contract call contract)");
    context->error_code = ret;
    res.status_code = EVMC_REVERT;
    return res;
  }

  /* Fill evmc_result */
  res.output_size = (size_t)receipt->return_data_len;
  res.output_data = (uint8_t *)malloc(res.output_size);
  memcpy((void *)res.output_data, receipt->return_data, res.output_size);
  res.release = release_result;
  if (msg->kind == EVMC_CREATE) {
    res.create_address = account_id_to_address(sub_gw_ctx->transaction_context.to_id);
  }

  ckb_debug("END call");

  return res;
}

evmc_bytes32 get_block_hash(struct evmc_host_context* context, int64_t number) {
  ckb_debug("BEGIN get_block_hash");
  evmc_bytes32 block_hash{};
  int ret = context->gw_ctx->sys_get_block_hash((void *)context->gw_ctx,
                                                number,
                                                (uint8_t *)block_hash.bytes);
  if (ret != 0) {
    context->error_code = ret;
    return block_hash;
  }
  ckb_debug("END get_block_hash");
  return block_hash;
}

void emit_log(struct evmc_host_context* context,
              const evmc_address* address,
              const uint8_t* data,
              size_t data_size,
              const evmc_bytes32 topics[],
              size_t topics_count) {
  ckb_debug("BEGIN emit_log");
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
  int ret = context->gw_ctx->sys_log((void *)context->gw_ctx,
                                     context->gw_ctx->transaction_context.to_id,
                                     (uint32_t) output_size,
                                     output);
  if (ret != 0) {
    context->error_code = ret;
  }
  free(output);
  ckb_debug("END emit_log");
  return;
}


/**
 * call/create contract
 *
 * Must allocate an account id before create contract
 */
int handle_message(void* ctx, size_t ctx_size) {
  ckb_debug("BEGIN handle_message");

  int ret;

  gw_context_t *gw_ctx = (gw_context_t *)ctx;
  /* Parse message */
  struct evmc_message msg;
  ckb_debug("BEGIN parse_message()");
  ret = parse_message(&msg, gw_ctx);
  ckb_debug("END parse_message()");
  if (ret != 0) {
    return ret;
  }

  evmc_address tx_origin = msg.sender;
  if (msg.depth > 0 ) {
    memcpy(tx_origin.bytes, gw_ctx->transaction_context.args + 1, 20);
  }

  /* Load account script (TODO: can be cached) */
  if (!script_loaded) {
    mol_seg_t script_seg;
    ret = load_account_script(gw_ctx, gw_ctx->transaction_context.to_id, &script_seg);
    if (ret != 0) {
      return ret;
    }
    mol_seg_t code_hash_seg = MolReader_Script_get_code_hash(&script_seg);
    mol_seg_t hash_type_seg = MolReader_Script_get_hash_type(&script_seg);
    mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
    mol_seg_t raw_args_seg = MolReader_Bytes_raw_bytes(&args_seg);
    script_loaded = true;
    memcpy(script_code_hash, code_hash_seg.ptr, 32);
    script_hash_type = *hash_type_seg.ptr;
    sudt_id = *(uint32_t *)(raw_args_seg.ptr);
    free((void *)script_seg.ptr);
  }

  struct evmc_host_context context { gw_ctx, ctx_size, tx_origin, 0 };

  uint8_t *code_data = NULL;
  size_t code_size = 0;
  if (msg.kind == EVMC_CREATE) {
    /* use input as code */
    code_data = (uint8_t *)msg.input_data;
    code_size = msg.input_size;
    msg.input_data = NULL;
    msg.input_size = 0;
    /* create account id */
    /* Include:
       - sudt id
       - sender account id
       - sender nonce (NOTE: only first 4 bytes (u32))
    */
    uint8_t args[40];
    memcpy(args, (uint8_t *)(&sudt_id), 4);
    memcpy(args + 4, (uint8_t *)(&gw_ctx->transaction_context.from_id), 4);
    // TODO: the nonce length can be optimized (change nonce data type, u32 is not enough)
    ret = gw_ctx->sys_load_nonce(gw_ctx, gw_ctx->transaction_context.from_id, args + 8);
    if (ret != 0) {
      return ret;
    }
    mol_seg_t new_script_seg;
    uint32_t new_account_id;
    ret = build_script(script_code_hash, script_hash_type, args, 12, &new_script_seg);
    if (ret != 0) {
      return ret;
    }
    ret = gw_ctx->sys_create(gw_ctx, new_script_seg.ptr, new_script_seg.size, &new_account_id);
    if (ret != 0) {
      return ret;
    }
    gw_ctx->transaction_context.to_id = new_account_id;
  } else if (msg.kind == EVMC_CALL) {
    ret = load_account_code(gw_ctx,
                            gw_ctx->transaction_context.to_id,
                            &code_data,
                            &code_size);
    if (ret != 0) {
      return ret;
    }
    // Do nothing
  } else {
    // FIXME: handle special call kind
    return -1;
  }

  /* Execute the code in EVM */
  struct evmc_vm *vm = evmc_create_evmone();
  struct evmc_host_interface interface = { account_exists,
                                           get_storage, set_storage,
                                           get_balance,
                                           get_code_size, get_code_hash, copy_code,
                                           selfdestruct, call,
                                           get_tx_context,
                                           get_block_hash,
                                           emit_log };
  struct evmc_result res = vm->execute(vm,
                                       &interface,
                                       &context,
                                       EVMC_MAX_REVISION,
                                       &msg,
                                       code_data,
                                       code_size);
  if (context.error_code != 0)  {
    debug_print_int("context.error_code:", context.error_code);
    return context.error_code;
  }

  /* handle transfer logic */
  bool is_zero_value = true;
  for (int i = 0; i < 32; i++) {
    if (msg.value.bytes[i] != 0) {
      is_zero_value = false;
      break;
    }
  }
  if (!is_zero_value) {
    uint8_t value_u128_bytes[16];
    for (int i = 0; i < 16; i++) {
      value_u128_bytes[i] = msg.value.bytes[31-i];
    }
    uint128_t value_u128 = *(uint128_t *)value_u128_bytes;
    debug_print_int("from_id", gw_ctx->transaction_context.from_id);
    debug_print_int("to_id", gw_ctx->transaction_context.to_id);
    debug_print_int("transfer value", value_u128);
    ret = sudt_transfer(gw_ctx,
                        sudt_id,
                        gw_ctx->transaction_context.from_id,
                        gw_ctx->transaction_context.to_id,
                        value_u128);
    if (ret != 0) {
      ckb_debug("transfer failed");
      return ret;
    }
  }

  /* Store code though syscall */
  // TODO handle special create kind
  if (msg.kind == EVMC_CREATE) {
    uint32_t new_account_id = gw_ctx->transaction_context.to_id;
    uint8_t key[32];
    uint8_t data_hash[32];
    blake2b_hash(data_hash, (uint8_t *)res.output_data, res.output_size);
    gw_build_contract_code_key(new_account_id, key);
    ckb_debug("BEGIN store data key");
    ret = gw_ctx->sys_store(gw_ctx, new_account_id, key, data_hash);
    if (ret != 0) {
      return ret;
    }
    ckb_debug("BEGIN store data");
    ret = gw_ctx->sys_store_data(gw_ctx, res.output_size, (uint8_t *)res.output_data);
    ckb_debug("END store data");
    if (ret != 0) {
      return ret;
    }
  }

  debug_print_int("output size", res.output_size);
  gw_ctx->receipt.return_data_len = (uint32_t)res.output_size;
  memcpy(gw_ctx->receipt.return_data, res.output_data, res.output_size);
  debug_print_int("status_code", res.status_code);
  ckb_debug("END handle_message");
  return (int)res.status_code;
}
