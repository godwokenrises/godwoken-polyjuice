#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ckb_syscalls.h"
#include "godwoken.h"

#include <ethash/keccak.hpp>
#include <evmc/evmc.h>
#include <evmc/evmc.hpp>
#include <evmone/evmone.h>

#include "common.h"

/* https://stackoverflow.com/a/1545079 */
#pragma push_macro("errno")
#undef errno
#include "gw_syscalls.h"
#pragma pop_macro("errno")

#include "sudt_utils.h"
#include "polyjuice_utils.h"

#ifdef GW_GENERATOR
#include "generator/secp256k1_helper.h"
#else
#include "validator/secp256k1_helper.h"
#endif
#include "contracts.h"


#define is_create(kind) ((kind) == EVMC_CREATE || (kind) == EVMC_CREATE2)
#define is_special_call(kind) \
  ((kind) == EVMC_CALLCODE || (kind) == EVMC_DELEGATECALL)

/* Max data buffer size: 24KB */
#define MAX_DATA_SIZE 24576
#define POLYJUICE_SYSTEM_PREFIX 0xFF
#define POLYJUICE_CONTRACT_CODE 0x01
#define POLYJUICE_DESTRUCTED 0x02

static bool has_touched = false;
static uint8_t rollup_script_hash[32] = {0};
static uint32_t sudt_id = UINT32_MAX;
static uint32_t tx_origin_id = UINT32_MAX;
/* Receipt.contractAddress - The contract address created, if the transaction was a contract creation, otherwise null */
static uint32_t created_id = UINT32_MAX;
static uint32_t creator_account_id = UINT32_MAX;
static evmc_address tx_origin;
static uint8_t script_code_hash[32];
static uint8_t script_hash_type;

/* normal polyjuice contract account */
static const uint32_t NORMAL_ARGS_SIZE = 32 + 4 + 4 + 4;
/* create2 polyjuice contract account */
static const uint32_t CREATE2_ARGS_SIZE = 32 + 4 + 1 + 4 + 32 + 32;

void polyjuice_build_system_key(uint32_t id, uint8_t polyjuice_field_type,
                                uint8_t key[GW_KEY_BYTES]) {
  memset(key, 0, GW_KEY_BYTES);
  memcpy(key, (uint8_t*)(&id), sizeof(uint32_t));
  key[4] = POLYJUICE_SYSTEM_PREFIX;
  key[5] = polyjuice_field_type;
}

void polyjuice_build_contract_code_key(uint32_t id, uint8_t key[GW_KEY_BYTES]) {
  polyjuice_build_system_key(id, POLYJUICE_CONTRACT_CODE, key);
}
void polyjuice_build_destructed_key(uint32_t id, uint8_t key[GW_KEY_BYTES]) {
  polyjuice_build_system_key(id, POLYJUICE_DESTRUCTED, key);
}

int gw_increase_nonce(gw_context_t *ctx, uint32_t account_id, uint32_t *new_nonce) {
  uint8_t old_nonce_value[GW_VALUE_BYTES];
  int ret = ctx->sys_load_nonce(ctx, account_id, old_nonce_value);
  if (ret != 0) {
    return ret;
  }
  for (size_t i = 4; i < GW_VALUE_BYTES; i++) {
    if(old_nonce_value[i] != 0){
      return GW_ERROR_INVALID_DATA;
    }
  }
  uint32_t next_nonce = *((uint32_t *)old_nonce_value) + 1;

  uint8_t nonce_key[GW_KEY_BYTES];
  uint8_t nonce_value[GW_VALUE_BYTES];
  memset(nonce_value, 0, GW_VALUE_BYTES);
  gw_build_nonce_key(account_id, nonce_key);
  memcpy(nonce_value, (uint8_t *)(&next_nonce), 4);
#ifdef GW_GENERATOR
  ret = syscall(GW_SYS_STORE, nonce_key, nonce_value, 0, 0, 0, 0);
#else
  ret = gw_state_insert(&ctx->kv_state, nonce_key, nonce_value);
#endif
  if (ret != 0) {
    return ret;
  }
  if (new_nonce != NULL) {
    *new_nonce = next_nonce;
  }
  return 0;
}

int handle_message(gw_context_t* ctx,
                   uint32_t parent_from_id,
                   uint32_t parent_to_id,
                   const evmc_message* msg, struct evmc_result* res);
typedef int (*stream_data_loader_fn)(gw_context_t* ctx, long data_id,
                                     uint32_t* len, uint32_t offset,
                                     uint8_t* data);

struct evmc_host_context {
  gw_context_t* gw_ctx;
  const uint8_t* code_data;
  const size_t code_size;
  uint32_t from_id;
  uint32_t to_id;
  int error_code;
};

/**
   Message = [
     header     : [u8; 8]            0xff, 0xff, 0xff, "POLY", call_kind
     gas_limit  : u64                (little endian)
     gas_price  : u128               (little endian)
     value      : u128               (little endian)
     input_size : u32                (little endian)
     input_data : [u8; input_size]
   ]
 */
int parse_args(struct evmc_message* msg, uint128_t* gas_price,
               gw_context_t* ctx) {
  gw_transaction_context_t *tx_ctx = &ctx->transaction_context;
  debug_print_int("args_len", tx_ctx->args_len);
  if (tx_ctx->args_len < (8 + 8 + 16 + 16 + 4)) {
    ckb_debug("invalid polyjuice arguments data");
    return -1;
  }
  /* == Args decoder */
  size_t offset = 0;
  uint8_t* args = tx_ctx->args;

  /* args[0..8] magic header + call kind */
  static const uint8_t polyjuice_args_header[7] = {0xff, 0xff, 0xff, 'P', 'O', 'L', 'Y'};
  if (memcmp(polyjuice_args_header, args, 7) != 0) {
    debug_print_data("invalid polyjuice args header", args, 7);
    return -1;
  }
  evmc_call_kind kind = (evmc_call_kind)args[7];
  offset += 8;
  debug_print_int("[kind]", kind);

  /* args[8..16] gas limit  */
  int64_t gas_limit = (int64_t) (*(uint64_t*)(args + offset));
  offset += 8;
  debug_print_int("[gas_limit]", gas_limit);

  /* args[16..32] gas price */
  *gas_price = *((uint128_t*)(args + offset));
  offset += 16;
  debug_print_int("[gas_price]", (int64_t)(*gas_price));

  /* args[32..48] transfer value */
  evmc_uint256be value{0};
  for (size_t i = 0; i < 16; i++) {
    value.bytes[31 - i] = args[offset + i];
  }
  offset += 16;
  debug_print_data("[value]", value.bytes, 32);

  /* args[48..52] */
  uint32_t input_size = *((uint32_t*)(args + offset));
  offset += 4;
  debug_print_int("[input_size]", input_size);

  if (tx_ctx->args_len != (input_size + offset)) {
    ckb_debug("invalid polyjuice transaction");
    return -1;
  }

  /* args[52..52+input_size] */
  uint8_t* input_data = args + offset;
  debug_print_data("[input_data]", input_data, input_size);

  if (kind != EVMC_CALL && kind != EVMC_CREATE) {
    ckb_debug("invalid call kind");
    return -1;
  }

  int ret;
  evmc_address sender{0};
  ret = account_id_to_address(ctx, tx_ctx->from_id, &sender);
  if (ret != 0) {
    return ret;
  }
  evmc_address destination{0};
  ret = account_id_to_address(ctx, tx_ctx->to_id, &destination);
  if (ret != 0) {
    return ret;
  }
  tx_origin_id = tx_ctx->from_id;
  memcpy(tx_origin.bytes, sender.bytes, 20);

  msg->kind = kind;
  msg->flags = 0;
  msg->depth = 0;
  msg->value = value;
  msg->input_data = input_data;
  msg->input_size = input_size;
  msg->gas = gas_limit;
  msg->sender = sender;
  msg->destination = destination;
  msg->create2_salt = evmc_bytes32{};
  return 0;
}

int build_script(uint8_t code_hash[32], uint8_t hash_type, uint8_t* args,
                 uint32_t args_len, mol_seg_t* script_seg) {
  /* 1. Build Script by receipt.return_data */
  mol_seg_t args_seg;
  args_seg.size = 4 + args_len;
  args_seg.ptr = (uint8_t*)malloc(args_seg.size);
  if (args_seg.ptr == NULL) {
    return -1;
  }
  memcpy(args_seg.ptr, (uint8_t*)(&args_len), 4);
  memcpy(args_seg.ptr + 4, args, args_len);
  debug_print_data("script.args", args, args_len);
  debug_print_data("script.code_hash", code_hash, 32);
  debug_print_int("script.hash_type", hash_type);

  mol_builder_t script_builder;
  MolBuilder_Script_init(&script_builder);
  MolBuilder_Script_set_code_hash(&script_builder, code_hash, 32);
  MolBuilder_Script_set_hash_type(&script_builder, hash_type);
  MolBuilder_Script_set_args(&script_builder, args_seg.ptr, args_seg.size);
  mol_seg_res_t script_res = MolBuilder_Script_build(script_builder);
  free(args_seg.ptr);

  /* https://stackoverflow.com/a/1545079 */
#pragma push_macro("errno")
#undef errno
  if (script_res.errno != MOL_OK) {
    ckb_debug("molecule build script failed");
    return -1;
  }
#pragma pop_macro("errno")

  *script_seg = script_res.seg;

  debug_print_data("script ", script_seg->ptr, script_seg->size);
  if (MolReader_Script_verify(script_seg, false) != MOL_OK) {
    ckb_debug("built an invalid script");
    return -1;
  }
  return 0;
}

void release_result(const struct evmc_result* result) {
  if (result->output_data != NULL) {
    free((void*)result->output_data);
  }
  return;
}

int load_account_script(gw_context_t* gw_ctx, uint32_t account_id,
                        uint8_t* buffer, uint32_t buffer_size,
                        mol_seg_t* script_seg) {
  debug_print_int("load_account_script, account_id:", account_id);
  int ret;
  uint64_t len = buffer_size;
  ret = gw_ctx->sys_get_account_script(gw_ctx, account_id, &len, 0, buffer);
  if (ret != 0) {
    ckb_debug("load account script failed");
    return ret;
  }
  script_seg->ptr = buffer;
  script_seg->size = len;
  if (MolReader_Script_verify(script_seg, false) != MOL_OK) {
    ckb_debug("load account script: invalid script");
    return -1;
  }
  return 0;
}

int load_account_code(gw_context_t* gw_ctx, uint32_t account_id,
                      uint64_t* code_size, uint64_t offset, uint8_t* code) {

  int ret;
  uint8_t buffer[GW_MAX_SCRIPT_SIZE];
  mol_seg_t script_seg;
  ret = load_account_script(gw_ctx, account_id, buffer, GW_MAX_SCRIPT_SIZE, &script_seg);
  if (ret != 0) {
    return ret;
  }
  mol_seg_t code_hash_seg = MolReader_Script_get_code_hash(&script_seg);
  mol_seg_t hash_type_seg = MolReader_Script_get_hash_type(&script_seg);
  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t raw_args_seg = MolReader_Bytes_raw_bytes(&args_seg);
  if (raw_args_seg.size != NORMAL_ARGS_SIZE && raw_args_seg.size != CREATE2_ARGS_SIZE) {
    debug_print_int("invalid account script", account_id);
    debug_print_int("raw_args_seg.size", raw_args_seg.size);
    return -1;
  }
  if (memcmp(code_hash_seg.ptr, script_code_hash, 32) != 0
      || *hash_type_seg.ptr != script_hash_type
      /* compare rollup_script_hash */
      || memcmp(raw_args_seg.ptr, rollup_script_hash, 32) != 0
      /* compare creator account id */
      || creator_account_id != *(uint32_t *)(raw_args_seg.ptr + 32)) {
    debug_print_int("creator account id not match for account", account_id);
    return -1;
  }

  debug_print_int("load_account_code, account_id:", account_id);
  uint8_t key[32];
  uint8_t data_hash[32];
  polyjuice_build_contract_code_key(account_id, key);
  ret = gw_ctx->sys_load(gw_ctx, account_id, key, data_hash);
  if (ret != 0) {
    ckb_debug("sys_load failed");
    return ret;
  }
  debug_print_data("data_hash", data_hash, 32);

  bool is_data_hash_zero = true;
  for (size_t i = 0; i < 32; i++) {
    if (data_hash[i] != 0) {
      is_data_hash_zero = false;
      break;
    }
  }
  if (is_data_hash_zero) {
    ckb_debug("data hash all zero");
    *code_size = 0;
    return 0;
  }

  uint64_t old_code_size = *code_size;
  ret = gw_ctx->sys_load_data(gw_ctx, data_hash, code_size, offset, code);
  debug_print_data("code data", code, *code_size);
  if (ret != 0) {
    ckb_debug("sys_load_data failed");
    return ret;
  }
  if (*code_size > old_code_size) {
    ckb_debug("code can't be larger than MAX_DATA_SIZE");
    return -1;
  }
  return 0;
}

////////////////////////////////////////////////////////////////////////////
//// Callbacks
////////////////////////////////////////////////////////////////////////////
struct evmc_tx_context get_tx_context(struct evmc_host_context* context) {
  struct evmc_tx_context ctx{0};
  /* gas price = 1 */
  ctx.tx_gas_price.bytes[31] = 0x01;
  memcpy(ctx.tx_origin.bytes, tx_origin.bytes, 20);
  int ret = account_id_to_address(context->gw_ctx,
                                  context->gw_ctx->block_info.block_producer_id,
                                  &ctx.block_coinbase);
  if (ret != 0) {
    context->error_code = ret;
  }
  ctx.block_number = context->gw_ctx->block_info.number;
  /*
    block_timestamp      => second
    block_info.timestamp => millisecond
  */
  ctx.block_timestamp = context->gw_ctx->block_info.timestamp / 1000;
  /* Ethereum block gas limit */
  ctx.block_gas_limit = 12500000;
  /* 2500000000000000 */
  ctx.block_difficulty = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x08, 0xe1, 0xbc, 0x9b, 0xf0, 0x40, 0x00,
  };
  /* chain_id = creator_account_id */
  uint8_t *creator_account_id_ptr = (uint8_t *)(&creator_account_id);
  ctx.chain_id.bytes[31] = creator_account_id_ptr[0];
  ctx.chain_id.bytes[30] = creator_account_id_ptr[1];
  ctx.chain_id.bytes[29] = creator_account_id_ptr[2];
  ctx.chain_id.bytes[28] = creator_account_id_ptr[3];
  return ctx;
}

bool account_exists(struct evmc_host_context* context,
                    const evmc_address* address) {
  ckb_debug("BEGIN account_exists");
  uint32_t account_id = 0;
  int ret = address_to_account_id(context->gw_ctx, address, &account_id);
  if (ret != 0) {
    ckb_debug("address_to_account_id failed");
    context->error_code = ret;
    return false;
  }
  uint8_t script_hash[32];
  ret = context->gw_ctx->sys_get_script_hash_by_account_id(context->gw_ctx, account_id, script_hash);
  if (ret != 0) {
    context->error_code = ret;
    return false;
  }
  bool exists = false;
  for (int i = 0; i < 32; i++) {
    /* if account not exists script_hash will be zero */
    if (script_hash[i] != 0) {
      exists = true;
      break;
    }
  }
  ckb_debug("END account_exists");
  return exists;
}

evmc_bytes32 get_storage(struct evmc_host_context* context,
                         const evmc_address* address, const evmc_bytes32* key) {
  ckb_debug("BEGIN get_storage");
  evmc_bytes32 value{};
  int ret = context->gw_ctx->sys_load(context->gw_ctx, context->to_id,
                                      key->bytes, (uint8_t*)value.bytes);
  if (ret != 0) {
    ckb_debug("sys_load failed");
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
  int ret = context->gw_ctx->sys_store(context->gw_ctx, context->to_id,
                                       key->bytes, value->bytes);
  if (ret != 0) {
    ckb_debug("sys_store failed");
    context->error_code = ret;
  }
  /* TODO: more rich evmc_storage_status */
  ckb_debug("END set_storage");
  return EVMC_STORAGE_ADDED;
}

size_t get_code_size(struct evmc_host_context* context,
                     const evmc_address* address) {
  ckb_debug("BEGIN get_code_size");
  int ret;
  uint32_t account_id = 0;
  ret = address_to_account_id(context->gw_ctx, address, &account_id);
  if (ret != 0) {
    ckb_debug("address to account_id failed");
    context->error_code = ret;
    return 0;
  }
  uint8_t code[MAX_DATA_SIZE];
  uint64_t code_size = MAX_DATA_SIZE;
  ret = load_account_code(context->gw_ctx, account_id, &code_size, 0, code);
  if (ret != 0) {
    ckb_debug("load_account_code failed");
    context->error_code = ret;
    return 0;
  }
  ckb_debug("END get_code_size");
  return code_size;
}

evmc_bytes32 get_code_hash(struct evmc_host_context* context,
                           const evmc_address* address) {
  ckb_debug("BEGIN get_code_hash");
  evmc_bytes32 hash{};
  uint32_t account_id = 0;
  int ret = address_to_account_id(context->gw_ctx, address, &account_id);
  if (ret != 0) {
    ckb_debug("address_to_account_id failed");
    context->error_code = ret;
    return hash;
  }

  uint8_t code[MAX_DATA_SIZE];
  uint64_t code_size = MAX_DATA_SIZE;
  ret = load_account_code(context->gw_ctx, account_id, &code_size, 0, code);
  if (ret != 0) {
    ckb_debug("load_account_code failed");
    context->error_code = ret;
    return hash;
  }

  union ethash_hash256 hash_result = ethash::keccak256(code, code_size);
  memcpy(hash.bytes, hash_result.bytes, 32);
  ckb_debug("END get_code_hash");
  return hash;
}

size_t copy_code(struct evmc_host_context* context, const evmc_address* address,
                 size_t code_offset, uint8_t* buffer_data, size_t buffer_size) {
  ckb_debug("BEGIN copy_code");
  uint32_t account_id = 0;
  int ret = address_to_account_id(context->gw_ctx, address, &account_id);
  if (ret != 0) {
    ckb_debug("address to account_id failed");
    context->error_code = ret;
    return 0;
  }

  uint64_t code_size = (uint32_t)buffer_size;
  ret = load_account_code(context->gw_ctx, account_id, &code_size,
                          (uint32_t)code_offset, buffer_data);
  if (ret != 0) {
    ckb_debug("load account code failed");
    context->error_code = ret;
    return 0;
  }
  debug_print_data("code slice", buffer_data, buffer_size);
  ckb_debug("END copy_code");
  return 0;
}

evmc_uint256be get_balance(struct evmc_host_context* context,
                           const evmc_address* address) {
  ckb_debug("BEGIN get_balance");
  int ret;
  evmc_uint256be balance{};
  uint32_t account_id = 0;
  ret = address_to_account_id(context->gw_ctx, address, &account_id);
  if (ret != 0) {
    ckb_debug("address to account_id failed");
    context->error_code = ret;
    return balance;
  }

  uint128_t value_u128 = 0;
  ret = sudt_get_balance(context->gw_ctx, sudt_id, account_id, &value_u128);
  if (ret != 0) {
    ckb_debug("sudt_get_balance failed");
    context->error_code = -1;
    return balance;
  }
  uint8_t* value_ptr = (uint8_t*)(&value_u128);
  for (int i = 0; i < 16; i++) {
    balance.bytes[31 - i] = *(value_ptr + i);
  }
  ckb_debug("END get_balance");
  debug_print_int("account_id", account_id);
  debug_print_int("balance", value_u128);
  return balance;
}

void selfdestruct(struct evmc_host_context* context,
                  const evmc_address* address,
                  const evmc_address* beneficiary) {
  int ret;
  uint32_t beneficiary_account_id = 0;
  ckb_debug("BEGIN selfdestruct");
  ret = address_to_account_id(context->gw_ctx, beneficiary, &beneficiary_account_id);
  if (ret != 0) {
    ckb_debug("address to account_id failed");
    context->error_code = ret;
    return;
  }
  if (beneficiary_account_id == context->to_id) {
    ckb_debug("invalid beneficiary account");
    context->error_code = -1;
    return;
  }

  uint128_t balance;
  ret = sudt_get_balance(context->gw_ctx, sudt_id, context->to_id, &balance);
  if (ret != 0) {
    ckb_debug("get balance failed");
    context->error_code = ret;
    return;
  }
  if (balance > 0) {
    ret = sudt_transfer(context->gw_ctx, sudt_id, context->to_id,
                        beneficiary_account_id, balance);
    if (ret != 0) {
      ckb_debug("transfer beneficiary failed");
      context->error_code = ret;
      return;
    }
  }

  uint8_t raw_key[GW_KEY_BYTES];
  uint8_t value[GW_VALUE_BYTES];
  polyjuice_build_destructed_key(context->to_id, raw_key);
  memset(value, 1, GW_VALUE_BYTES);
#ifdef GW_VALIDATOR
  ret = gw_state_insert(&context->gw_ctx->kv_state, raw_key, value);
#else
  ret = syscall(GW_SYS_STORE, raw_key, value, 0, 0, 0, 0);
#endif
  if (ret != 0) {
    ckb_debug("update selfdestruct special key failed");
    context->error_code = ret;
  }
  ckb_debug("END selfdestruct");
  return;
}

struct evmc_result call(struct evmc_host_context* context,
                        const struct evmc_message* msg) {
  ckb_debug("BEGIN call");
  debug_print_data("call.sender", msg->sender.bytes, 20);
  debug_print_data("call.destination", msg->destination.bytes, 20);
  int ret;
  struct evmc_result res;
  res.output_data = NULL;
  res.release = release_result;
  gw_context_t* gw_ctx = context->gw_ctx;

  if (msg->depth > (int32_t)UINT16_MAX) {
    ckb_debug("depth too large");
    context->error_code = -1;
    res.status_code = EVMC_REVERT;
    return res;
  }

  precompiled_contract_gas_fn contract_gas;
  precompiled_contract_fn contract;
  if (match_precompiled_address(&msg->destination, &contract_gas, &contract)) {
    uint64_t gas_cost = 0;
    ret = contract_gas(msg->input_data, msg->input_size, &gas_cost);
    if (ret != 0) {
      ckb_debug("call pre-compiled contract gas failed");
      context->error_code = ret;
      res.status_code = EVMC_REVERT;
      return res;
    }
    if ((uint64_t)msg->gas < gas_cost) {
      ckb_debug("call pre-compiled contract out of gas");
      res.status_code = EVMC_OUT_OF_GAS;
      return res;
    }
    res.gas_left = msg->gas - (int64_t)gas_cost;
    ret = contract(gw_ctx,
                   context->code_data, context->code_size,
                   msg->flags == EVMC_STATIC,
                   msg->input_data, msg->input_size,
                   (uint8_t**)&res.output_data, &res.output_size);
    if (ret != 0) {
      ckb_debug("call pre-compiled contract failed");
      context->error_code = ret;
      res.status_code = EVMC_REVERT;
      return res;
    }
    res.status_code = EVMC_SUCCESS;
    debug_print_data("output data", res.output_data, res.output_size);
  } else {
    ret = handle_message(gw_ctx, context->from_id, context->to_id, msg, &res);
    if (ret != 0) {
      ckb_debug("inner call failed (transfer/contract call contract)");
      context->error_code = ret;
      res.status_code = EVMC_REVERT;
      return res;
    }
  }

  /* Increase context->to_id's nonce */
  if (is_create(msg->kind)) {
    ret = gw_increase_nonce(context->gw_ctx, context->to_id, NULL);
    if (ret != 0) {
      ckb_debug("increase nonce failed");
      context->error_code = ret;
      res.status_code = EVMC_REVERT;
      return res;
    }
  }
  debug_print_int("call.res.status_code", res.status_code);
  ckb_debug("END call");

  return res;
}

evmc_bytes32 get_block_hash(struct evmc_host_context* context, int64_t number) {
  ckb_debug("BEGIN get_block_hash");
  evmc_bytes32 block_hash{};
  int ret = context->gw_ctx->sys_get_block_hash(context->gw_ctx, number,
                                                (uint8_t*)block_hash.bytes);
  if (ret != 0) {
    ckb_debug("sys_get_block_hash failed");
    context->error_code = ret;
    return block_hash;
  }
  ckb_debug("END get_block_hash");
  return block_hash;
}

void emit_log(struct evmc_host_context* context, const evmc_address* address,
              const uint8_t* data, size_t data_size,
              const evmc_bytes32 topics[], size_t topics_count) {
  ckb_debug("BEGIN emit_log");
  debug_print_data("log.data", data, data_size);
  /*
    output[ 0..20]                     = callee_contract.address
    output[20..24]                     = data_size_u32
    output[24..24+data_size]           = data
    ouptut[24+data_size..28+data_size] = topics_count_u32
    ouptut[28+data_size..]             = topics
   */
  size_t output_size = 20 + (4 + data_size) + (4 + topics_count * 32);
  uint8_t* output = (uint8_t*)malloc(output_size);
  if (output == NULL) {
    context->error_code = -1;
    return;
  }
  uint32_t data_size_u32 = (uint32_t)(data_size);
  uint32_t topics_count_u32 = (uint32_t)(topics_count);

  uint8_t* output_current = output;
  memcpy(output_current, address->bytes, 20);
  output_current += 20;
  memcpy(output_current, (uint8_t*)(&data_size_u32), 4);
  output_current += 4;
  memcpy(output_current, data, data_size);
  output_current += data_size;
  memcpy(output_current, (uint8_t*)(&topics_count_u32), 4);
  output_current += 4;
  for (size_t i = 0; i < topics_count; i++) {
    debug_print_data("log.topic", topics[i].bytes, 32);
    memcpy(output_current, topics[i].bytes, 32);
    output_current += 32;
  }
  int ret = context->gw_ctx->sys_log(context->gw_ctx, context->to_id,
                                     GW_LOG_POLYJUICE_USER, (uint32_t)output_size, output);
  if (ret != 0) {
    ckb_debug("sys_log failed");
    context->error_code = ret;
  }
  free(output);
  ckb_debug("END emit_log");
  return;
}

int check_destructed(gw_context_t* ctx, uint32_t to_id) {
  int ret;
  uint8_t destructed_raw_key[GW_KEY_BYTES];
  uint8_t destructed_raw_value[GW_VALUE_BYTES] = {0};
  polyjuice_build_destructed_key(to_id, destructed_raw_key);
#ifdef GW_VALIDATOR
  ret = gw_state_fetch(&ctx->kv_state, destructed_raw_key, destructed_raw_value);
#else
  ret = syscall(GW_SYS_LOAD, destructed_raw_key, destructed_raw_value, 0, 0, 0, 0);
#endif
  if (ret != 0) {
    ckb_debug("load destructed key failed");
    return -1;
  }
  bool destructed = true;
  for (int i = 0; i < GW_VALUE_BYTES; i++) {
    if (destructed_raw_value[0] == 0) {
      destructed = false;
      break;
    }
  }
  if (destructed) {
    ckb_debug("call a contract that was already destructed");
    return -1;
  }
  return 0;
}

int load_globals(gw_context_t* ctx, uint32_t to_id, evmc_call_kind call_kind) {

  uint8_t buffer[GW_MAX_SCRIPT_SIZE];
  mol_seg_t script_seg;
  int ret = load_account_script(ctx, to_id, buffer, GW_MAX_SCRIPT_SIZE, &script_seg);
  if (ret != 0) {
    return ret;
  }
  mol_seg_t code_hash_seg = MolReader_Script_get_code_hash(&script_seg);
  mol_seg_t hash_type_seg = MolReader_Script_get_hash_type(&script_seg);
  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t raw_args_seg = MolReader_Bytes_raw_bytes(&args_seg);

  memcpy(script_code_hash, code_hash_seg.ptr, 32);
  script_hash_type = *hash_type_seg.ptr;

  uint8_t creator_script_buffer[GW_MAX_SCRIPT_SIZE];
  mol_seg_t creator_script_seg;
  mol_seg_t *creator_raw_args_seg_ptr = NULL;
  if (raw_args_seg.size == 36) {
    /* polyjuice creator account */
    creator_account_id = to_id;
    creator_raw_args_seg_ptr = &raw_args_seg;
  } else if (raw_args_seg.size == NORMAL_ARGS_SIZE || raw_args_seg.size == CREATE2_ARGS_SIZE) {
    /* read creator account and then read sudt id from it */
    creator_account_id = *(uint32_t *)(raw_args_seg.ptr + 32);
    int ret = load_account_script(ctx,
                                  creator_account_id,
                                  creator_script_buffer,
                                  GW_MAX_SCRIPT_SIZE,
                                  &creator_script_seg);
    if (ret != 0) {
      return ret;
    }
    mol_seg_t creator_code_hash_seg = MolReader_Script_get_code_hash(&creator_script_seg);
    mol_seg_t creator_hash_type_seg = MolReader_Script_get_hash_type(&creator_script_seg);
    mol_seg_t creator_args_seg = MolReader_Script_get_args(&creator_script_seg);
    mol_seg_t creator_raw_args_seg = MolReader_Bytes_raw_bytes(&creator_args_seg);
    if (memcmp(creator_code_hash_seg.ptr, code_hash_seg.ptr, 32) != 0
        || *creator_hash_type_seg.ptr != *hash_type_seg.ptr
        /* compare rollup_script_hash */
        || memcmp(creator_raw_args_seg.ptr, raw_args_seg.ptr, 32) != 0
        || creator_raw_args_seg.size != 36) {
      debug_print_int("invalid creator account id in normal contract account script args", creator_account_id);
      return -1;
    }
    creator_raw_args_seg_ptr = &creator_raw_args_seg;
  } else {
    debug_print_data("invalid to account script args", raw_args_seg.ptr, raw_args_seg.size);
    return -1;
  }

  memcpy(rollup_script_hash, creator_raw_args_seg_ptr->ptr, 32);
  sudt_id = *(uint32_t *)(creator_raw_args_seg_ptr->ptr + 32);
  debug_print_data("rollup_script_hash", rollup_script_hash, 32);
  debug_print_int("sudt id", sudt_id);
  return 0;
}

int create_new_account(gw_context_t* ctx,
                       const evmc_message* msg,
                       uint32_t from_id,
                       uint32_t* to_id,
                       uint8_t* code_data,
                       size_t code_size) {
  int ret = 0;
  uint8_t script_args[128];
  uint32_t script_args_len = 0;
  if (msg->kind == EVMC_CREATE) {
    /* create account id
       Include:
       - [32 bytes] rollup type hash
       - [ 4 bytes] creator account id (chain id)
       - [ 4 bytes] sender account id
       - [ 4 bytes] sender nonce (NOTE: only use first 4 bytes (u32))
    */
    debug_print_int("from_id", from_id);
    debug_print_int("to_id", *to_id);
    memcpy(script_args, rollup_script_hash, 32);
    memcpy(script_args + 32, (uint8_t*)(&creator_account_id), 4);
    memcpy(script_args + (32 + 4), (uint8_t*)(&from_id), 4);
    ret = ctx->sys_load_nonce(ctx, from_id, script_args + (32 + 4 + 4));
    if (ret != 0) {
      return ret;
    }
    script_args_len = 32 + 4 + 4 + 4;
  } else if (msg->kind == EVMC_CREATE2) {
    /* create account id
       Include:
       - [32 bytes] rollup type hash
       - [ 4 bytes] creator account id (chain id)
       - [ 1 byte ] 0xff (refer to ethereum)
       - [ 4 bytes] sender account id
       - [32 bytes] create2_salt
       - [32 bytes] keccak256(init_code)
    */
    memcpy(script_args, rollup_script_hash, 32);
    memcpy(script_args + 32, (uint8_t*)(&creator_account_id), 4);
    script_args[32 + 4] = 0xff;
    memcpy(script_args + (32 + 4 + 1), (uint8_t*)(&from_id), 4);
    memcpy(script_args + (32 + 4 + 1 + 4), msg->create2_salt.bytes, 32);
    debug_print_data("create2 init_code", code_data, code_size);
    union ethash_hash256 hash_result = ethash::keccak256(code_data, code_size);
    memcpy(script_args + (32 + 4 + 1 + 4 + 32), hash_result.bytes, 32);
    script_args_len = 32 + 4 + 1 + 4 + 32 + 32;
  } else {
    ckb_debug("unreachable");
    return -1;
  }
  if (script_args_len > 0) {
    mol_seg_t new_script_seg;
    uint32_t new_account_id;
    ret = build_script(script_code_hash, script_hash_type, script_args,
                       script_args_len, &new_script_seg);
    if (ret != 0) {
      return ret;
    }
    ret = ctx->sys_create(ctx, new_script_seg.ptr, new_script_seg.size,
                          &new_account_id);
    if (ret != 0) {
      debug_print_int("sys_create error", ret);
      ckb_debug("create account failed assume account already created by meta_contract");
      uint8_t script_hash[32];
      blake2b_hash(script_hash, new_script_seg.ptr, new_script_seg.size);
      ret = ctx->sys_get_account_id_by_script_hash(ctx, script_hash, &new_account_id);
      if (ret != 0) {
        return ret;
      }
    }
    free(new_script_seg.ptr);
    *to_id = new_account_id;
    debug_print_int(">> new to id", *to_id);
  }
  return 0;
}

int handle_transfer(gw_context_t* ctx,
                    const evmc_message* msg,
                    uint32_t from_id,
                    uint32_t to_id,
                    uint32_t tx_origin_id,
                    bool to_id_is_eoa) {
  int ret;
  bool is_zero_value = true;
  for (int i = 0; i < 32; i++) {
    if (msg->value.bytes[i] != 0) {
      is_zero_value = false;
      break;
    }
  }
  if (!is_zero_value) {
    uint8_t value_u128_bytes[16];
    for (int i = 0; i < 16; i++) {
      value_u128_bytes[i] = msg->value.bytes[31 - i];
    }
    uint128_t value_u128 = *(uint128_t*)value_u128_bytes;
    debug_print_int("from_id", from_id);
    debug_print_int("to_id", to_id);
    debug_print_int("transfer value", value_u128);
    ret = sudt_transfer(ctx, sudt_id, from_id, to_id, value_u128);
    if (ret != 0) {
      ckb_debug("transfer failed");
      return ret;
    }
  }

  if (msg->kind == EVMC_CALL && from_id == tx_origin_id && to_id_is_eoa) {
    ckb_debug("transfer value from eoa to eoa");
    return -1;
  }

  return 0;
}

int execute_in_evmone(gw_context_t* ctx,
                      evmc_message* msg,
                      uint32_t _parent_from_id,
                      uint32_t from_id,
                      uint32_t to_id,
                      const uint8_t* code_data,
                      const size_t code_size,
                      bool to_id_is_eoa,
                      struct evmc_result* res) {
  bool transfer_only = !is_create(msg->kind) && msg->input_size == 0;
  debug_print_int("to_id_is_eoa", to_id_is_eoa);
  debug_print_int("transfer_only", transfer_only);
  struct evmc_host_context context {ctx, code_data, code_size, from_id, to_id, 0};
  struct evmc_vm* vm = evmc_create_evmone();
  struct evmc_host_interface interface = {account_exists, get_storage,    set_storage,    get_balance,
                                          get_code_size,  get_code_hash,  copy_code,      selfdestruct,
                                          call,           get_tx_context, get_block_hash, emit_log};
  if (!to_id_is_eoa && !transfer_only) {
    /* Execute the code in EVM */
    int ret;
    ret = account_id_to_address(ctx, from_id, &msg->sender);
    if (ret != 0) {
      return ret;
    }
    ret = account_id_to_address(ctx, to_id, &msg->destination);
    if (ret != 0) {
      return ret;
    }

    debug_print_int("code size", code_size);
    debug_print_data("msg.input_data", msg->input_data, msg->input_size);
    *res = vm->execute(vm, &interface, &context, EVMC_MAX_REVISION, msg,
                       code_data, code_size);
    if (context.error_code != 0) {
      debug_print_int("context.error_code", context.error_code);
      return context.error_code;
    }
    if (res->gas_left < 0) {
      ckb_debug("gas not enough");
      return EVMC_OUT_OF_GAS;
    }
  } else {
    res->output_data = NULL;
    res->release = NULL;
    res->output_size = 0;
    res->status_code = EVMC_SUCCESS;
  }
  return 0;
}

int store_contract_code(gw_context_t* ctx,
                        uint32_t to_id,
                        struct evmc_result* res) {
  int ret;
  uint8_t key[32];
  uint8_t data_hash[32];
  blake2b_hash(data_hash, (uint8_t*)res->output_data, res->output_size);
  polyjuice_build_contract_code_key(to_id, key);
  ckb_debug("BEGIN store data key");
  debug_print_data("data_hash", data_hash, 32);
  ret = ctx->sys_store(ctx, to_id, key, data_hash);
  if (ret != 0) {
    return ret;
  }
  ckb_debug("BEGIN store data");
  ret = ctx->sys_store_data(ctx, res->output_size, (uint8_t*)res->output_data);
  ckb_debug("END store data");
  if (ret != 0) {
    return ret;
  }
  ret = account_id_to_address(ctx, to_id, &res->create_address);
  if (ret != 0) {
    return ret;
  }
  return 0;
}

/**
 * call/create contract
 *
 * Must allocate an account id before create contract
 */
int handle_message(gw_context_t* ctx,
                   uint32_t parent_from_id,
                   uint32_t parent_to_id,
                   const evmc_message* msg_origin, struct evmc_result* res) {
  ckb_debug("BEGIN handle_message");

  evmc_message msg = *msg_origin;

  int ret;

  uint32_t to_id;
  uint32_t from_id;
  ret = address_to_account_id(ctx, &(msg.destination), &to_id);
  if (ret != 0) {
    ckb_debug("address to account id failed");
    return -1;
  }
  if (msg.kind == EVMC_DELEGATECALL) {
    from_id = parent_from_id;
  } else {
    ret = address_to_account_id(ctx, &(msg.sender), &from_id);
    if (ret != 0) {
      ckb_debug("address to account id failed");
      return -1;
    }
  }

  /* Check if target contract is destructed */
  if (!is_create(msg.kind)) {
    ret = check_destructed(ctx, to_id);
    if (ret != 0) {
      return ret;
    }
  }

  /* Load: validator_code_hash, hash_type, sudt_id */
  if (!has_touched) {
    ret = load_globals(ctx, to_id, msg.kind);
    if (ret != 0) {
      return ret;
    }
    has_touched = true;
    if (msg.kind == EVMC_CREATE) {
      /* only the entrance to_id should be rewrite to 0, since it is given by
         user to locate the polyjuice backend */
      to_id = 0;
    }
  }

  /* Load contract code from evmc_message or by sys_load_data */
  uint8_t* code_data = NULL;
  size_t code_size = 0;
  bool to_id_is_eoa = false;
  uint8_t code_data_buffer[MAX_DATA_SIZE];
  uint64_t code_size_u32 = MAX_DATA_SIZE;
  if (is_create(msg.kind)) {
    /* use input as code */
    code_data = (uint8_t*)msg.input_data;
    code_size = msg.input_size;
    msg.input_data = NULL;
    msg.input_size = 0;
  } else {
    /* call kind: CALL/CALLCODE/DELEGATECALL */
    if (msg.input_size == 0) {
      /* call EoA account */
      to_id_is_eoa = true;
    } else {
      ret = load_account_code(ctx, to_id, &code_size_u32, 0, code_data_buffer);
      if (ret != 0) {
        return ret;
      }
      if (code_size_u32 == 0) {
        debug_print_int("empty contract code for account", to_id);
        return -1;
      }
      code_data = code_data_buffer;
      code_size = (size_t)code_size_u32;
    }
  }

  /* Handle special call: CALLCODE/DELEGATECALL */
  if (is_special_call(msg.kind)) {
    /* This action must after load the contract code */
    to_id = parent_to_id;
  }

  /* Create new account by script */
  /* NOTE: to_id may be rewritten */
  if (is_create(msg.kind)) {
    ret = create_new_account(ctx, &msg, from_id, &to_id, code_data, code_size);
    if (ret != 0) {
      return ret;
    }

    /* It's a creation polyjuice transaction */
    if (parent_from_id == UINT32_MAX && parent_to_id == UINT32_MAX) {
      created_id = to_id;
    }
  }

  /* Handle transfer logic.
     NOTE: MUST do this before vm.execute and after to_id finalized */
  ret = handle_transfer(ctx, &msg, from_id, to_id, tx_origin_id, to_id_is_eoa);
  if (ret != 0) {
    return ret;
  }

  /* NOTE: msg and res are updated */
  ret = execute_in_evmone(ctx, &msg, parent_from_id, from_id, to_id, code_data, code_size, to_id_is_eoa, res);
  if (ret != 0) {
    return ret;
  }

  /* Store contract code though syscall */
  if (is_create(msg.kind)) {
    ret = store_contract_code(ctx, to_id, res);
    if (ret != 0) {
      return ret;
    }
  }

  debug_print_data("output data", res->output_data, res->output_size);
  debug_print_int("output size", res->output_size);
  debug_print_int("status_code", res->status_code);
  ckb_debug("END handle_message");
  return (int)res->status_code;
}

int emit_evm_result_log(gw_context_t* ctx, const uint64_t gas_used, const int status_code) {
  /*
    data = { gasUsed: u64, cumulativeGasUsed: u64, contractAddress: u32, status_code: u32 }

    data[ 0.. 8] = gas_used
    data[ 8..16] = cumulative_gas_used
    data[16..20] = created_id (UINT32_MAX means not created)
    data[20..24] = status_code (EVM status_code)
   */
  uint64_t cumulative_gas_used = gas_used;
  uint32_t status_code_u32 = (uint32_t)status_code;

  uint32_t data_size = 8 + 8 + 4 + 4 + 4;
  uint8_t data[8 + 8 + 4 + 4 + 4] = {0};
  uint8_t *ptr = data;
  memcpy(ptr, (uint8_t *)(&gas_used), 8);
  ptr += 8;
  memcpy(ptr, (uint8_t *)(&cumulative_gas_used), 8);
  ptr += 8;
  memcpy(ptr, (uint8_t *)(&created_id), 4);
  ptr += 4;
  memcpy(ptr, (uint8_t *)(&status_code_u32), 4);
  ptr += 4;

  /* NOTE: if create account failed the `to_id` will also be `context->to_id` */
  uint32_t to_id = created_id == UINT32_MAX ? ctx->transaction_context.to_id : created_id;
  int ret = ctx->sys_log(ctx, to_id, GW_LOG_POLYJUICE_SYSTEM, data_size, data);
  if (ret != 0) {
    ckb_debug("sys_log evm result failed");
    return -1;
  }
  return 0;
}

int run_polyjuice() {
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
  ret = parse_args(&msg, &gas_price, &context);
  ckb_debug("END parse_message()");
  if (ret != 0) {
    return ret;
  }

  struct evmc_result res;
  int ret_handle_message = handle_message(&context, UINT32_MAX, UINT32_MAX, &msg, &res);
  uint64_t gas_used = (uint64_t)(msg.gas - res.gas_left);
  ret = emit_evm_result_log(&context, gas_used, res.status_code);
  if (ret != 0) {
    ckb_debug("emit_evm_result_log failed");
    return ret;
  }
  if (ret_handle_message != 0) {
    ckb_debug("handle message failed");
    return ret_handle_message;
  }

  ret = context.sys_set_program_return_data(&context, (uint8_t*)res.output_data,
                                            res.output_size);
  if (ret != 0) {
    ckb_debug("set return data failed");
    return ret;
  }

  /* Handle transaction fee */
  if (res.gas_left < 0) {
    ckb_debug("gas not enough");
    return -1;
  }
  if (msg.gas < res.gas_left) {
    ckb_debug("unreachable!");
    return -1;
  }
  uint128_t fee = gas_price * (uint128_t)gas_used;
  debug_print_int("gas limit", msg.gas);
  debug_print_int("gas left", res.gas_left);
  debug_print_int("gas price", gas_price);
  debug_print_int("fee", fee);
  ret = sudt_pay_fee(&context, sudt_id, context.transaction_context.from_id, fee);
  if (ret != 0) {
    debug_print_int("pay fee to block_producer failed", ret);
    return ret;
  }

  ret = gw_finalize(&context);
  if (ret != 0) {
    return ret;
  }
  return 0;
}
