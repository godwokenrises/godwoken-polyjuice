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
#include <evmc/evmc.hpp>
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

/* account script buffer sisze: 32KB */
#define ACCOUNT_SCRIPT_BUFSIZE 32768

int handle_message(gw_context_t* ctx);

struct evmc_host_context {
  gw_context_t* gw_ctx;
  evmc_address tx_origin;
  int error_code;
  uint8_t *script_code_hash;
  uint8_t script_hash_type;
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
int init_message(struct evmc_message *msg, gw_context_t* ctx) {
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

void release_result(const struct evmc_result* result) {
  free((void *)result->output_data);
  return;
}


int load_account_code(gw_context_t *gw_ctx,
                      uint32_t account_id,
                      mol_seg_t *script_seg,
                      uint8_t **code,
                      size_t *code_size) {
  int ret;
  size_t total_size = 0;
  size_t buffer_size = ACCOUNT_SCRIPT_BUFSIZE;
  uint32_t len = (uint32_t) buffer_size;
  uint8_t *buffer = (uint8_t *)malloc(buffer_size);
  uint8_t *ptr = buffer;
  size_t offset = 0;
  while (true) {
    ret = gw_ctx->sys_get_account_script((void *)gw_ctx,
                                         account_id,
                                         &len,
                                         offset,
                                         ptr);
    if (ret != 0) {
      free(buffer);
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

  script_seg->ptr = buffer;
  script_seg->size = total_size;
  if (MolReader_Script_verify(script_seg, false) != MOL_OK) {
    ckb_debug("verify script failed");
    return -1;
  }
  mol_seg_t args_seg = MolReader_Script_get_args(script_seg);
  mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
  *code_size = *((uint32_t *)args_bytes_seg.ptr);
  *code = args_bytes_seg.ptr + 4;
  debug_print_int("loaded code size", *code_size);
  debug_print_data("loaded code data", *code, *code_size);

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
  uint32_t account_id;
  int ret = address_to_account_id(address, &account_id);
  if (ret != 0) {
    context->error_code = ret;
  }
  ckb_debug("END account_exists");
  return ret == 0;
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
  mol_seg_t script_seg;
  uint8_t *code = NULL;
  size_t code_size;
  ret = load_account_code(context->gw_ctx, account_id, &script_seg, &code, &code_size);
  if (ret != 0) {
    context->error_code = ret;
    return 0;
  }
  free((void *)script_seg.ptr);
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

  mol_seg_t script_seg;
  uint8_t *code = NULL;
  size_t code_size;
  ret = load_account_code(context->gw_ctx, account_id, &script_seg, &code, &code_size);
  if (ret != 0) {
    context->error_code = ret;
    return hash;
  }

  union ethash_hash256 hash_result = ethash::keccak256(code, code_size);
  memcpy(hash.bytes, hash_result.bytes, 32);
  free((void *)script_seg.ptr);
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
  evmc_uint256be balance{};
  uint32_t account_id;
  int ret = address_to_account_id(address, &account_id);
  if (ret != 0) {
    return balance;
  }

  ckb_debug("END copy_code");
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
  ckb_debug("BEGIN call");
  int ret;
  struct evmc_result res;
  gw_context_t *gw_ctx = context->gw_ctx;

  uint32_t to_id;
  ret = address_to_account_id(&(msg->destination), &to_id);
  if (ret != 0) {
    context->error_code = ret;
    res.status_code = EVMC_REVERT;
    return res;
  }

  if (msg->depth > (int32_t)UINT16_MAX) {
    // ERROR: depth too large
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
  gw_context_t sub_gw_ctx;
  ret = create_sub_context(gw_ctx, &sub_gw_ctx, from_id, to_id, args, args_len);
  if (ret != 0) {
    context->error_code = ret;
    res.status_code = EVMC_REVERT;
    return res;
  }
  gw_call_receipt_t *receipt = &sub_gw_ctx.receipt;

  /* TODO: handle special kind (CREATE2/CALLCODE/DELEGATECALL)*/
  if (msg->kind == EVMC_CALL) {
    ret = handle_message(&sub_gw_ctx);
    memset(res.create_address.bytes, 0, 20);
  } else if (msg->kind == EVMC_CREATE) {
    /* assert(to_id == 0) */
    if (to_id != 0) {
      context->error_code = ret;
      res.status_code = EVMC_REVERT;
      return res;
    }

    ret = handle_message(&sub_gw_ctx);
    if (ret != 0) {
      context->error_code = ret;
      res.status_code = EVMC_REVERT;
      return res;
    }

    /* 1. Build Script by receipt.return_data */
    mol_seg_t args_seg;
    args_seg.size = 4 + receipt->return_data_len;
    args_seg.ptr = (uint8_t *)malloc(args_seg.size);
    memcpy(args_seg.ptr, (uint8_t *)(&(receipt->return_data_len)), 4);
    memcpy(args_seg.ptr + 4, receipt->return_data, receipt->return_data_len);

    mol_builder_t script_builder;
    MolBuilder_Script_init(&script_builder);
    MolBuilder_Script_set_code_hash(&script_builder, context->script_code_hash, 32);
    MolBuilder_Script_set_hash_type(&script_builder, context->script_hash_type);
    MolBuilder_Script_set_args(&script_builder, args_seg.ptr, args_seg.size);
    mol_seg_res_t script_res = MolBuilder_Script_build(script_builder);
    // Because errno is keyword
    uint8_t error_num = *(uint8_t *)(&script_res);
    if (error_num != MOL_OK) {
      /* ERROR: build script failed */
      context->error_code = error_num;
      res.status_code = EVMC_REVERT;
      return res;
    }
    mol_seg_t new_script_seg = script_res.seg;

    /* 2. Create account by Script */
    /* 3. Get account id */
    uint32_t new_account_id;
    ret = gw_ctx->sys_create((void *)gw_ctx, new_script_seg.ptr, new_script_seg.size, &new_account_id);
    if (ret != 0) {
      context->error_code = ret;
      res.status_code = EVMC_REVERT;
      return res;
    }

    /* 4. Set account id to sub_gw_ctx.transaction_context.to_id */
    sub_gw_ctx.transaction_context.to_id = new_account_id;

    /* 5. Set res.create_address by sub_gw_ctx.transaction_context.to_id */
    res.create_address = account_id_to_address(sub_gw_ctx.transaction_context.to_id);
  } else {
    /* ERROR: Invalid call kind */
    context->error_code = -1;
    res.status_code = EVMC_REVERT;
    return res;
  }

  if (ret != 0) {
    context->error_code = ret;
    res.status_code = EVMC_REVERT;
    return res;
  }

  /* Fill evmc_result */
  res.output_size = (size_t)receipt->return_data_len;
  res.output_data = (uint8_t *)malloc(res.output_size);
  memcpy((void *)res.output_data, receipt->return_data, res.output_size);
  res.release = release_result;

  /* FIXME: handle transfer logic */
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
int handle_message(gw_context_t* ctx) {
  ckb_debug("BEGIN handle_message");

  int ret;

  struct evmc_message msg;
  ckb_debug("BEGIN init_message()");
  ret = init_message(&msg, ctx);
  ckb_debug("END init_message()");
  if (ret != 0) {
    return ret;
  }

  struct evmc_vm *vm = evmc_create_evmone();
  struct evmc_host_interface interface = { account_exists,
                                           get_storage, set_storage,
                                           get_balance,
                                           get_code_size, get_code_hash, copy_code,
                                           selfdestruct, call,
                                           get_tx_context,
                                           get_block_hash,
                                           emit_log };
  evmc_address tx_origin = msg.sender;
  if (msg.depth > 0 ) {
    memcpy(tx_origin.bytes, ctx->transaction_context.args + 1, 20);
  }
  mol_seg_t script_seg;
  uint8_t *code_data = NULL;
  size_t code_size = 0;
  ret = load_account_code(ctx,
                          ctx->transaction_context.to_id,
                          &script_seg,
                          &code_data,
                          &code_size);
  mol_seg_t code_hash_seg = MolReader_Script_get_code_hash(&script_seg);
  mol_seg_t hash_type_seg = MolReader_Script_get_hash_type(&script_seg);
  if (code_hash_seg.size != 32) {
    // ERROR: invalid code hash length
    return -1;
  }
  uint8_t script_code_hash[32];
  uint8_t script_hash_type = *hash_type_seg.ptr;
  memcpy(script_code_hash, code_hash_seg.ptr, code_hash_seg.size);
  free((void *)script_seg.ptr);

  if (ret != 0) {
    return ret;
  }
  struct evmc_host_context context { ctx, tx_origin, 0, script_code_hash, script_hash_type };

  const uint8_t *current_code_data = code_data;
  size_t current_code_size = code_size;
  if (msg.kind == EVMC_CREATE) {
    current_code_data = msg.input_data;
    current_code_size = msg.input_size;
    msg.input_data = NULL;
    msg.input_size = 0;
  } else if (msg.kind == EVMC_CALL) {
    // Do nothing
  } else {
    // FIXME: handle special call kind
    return -1;
  }
  struct evmc_result res = vm->execute(vm,
                                       &interface,
                                       &context,
                                       EVMC_MAX_REVISION,
                                       &msg,
                                       current_code_data,
                                       current_code_size);
  if (context.error_code != 0)  {
    return context.error_code;
  }

  debug_print_int("output size", res.output_size);
  ctx->receipt.return_data_len = (uint32_t)res.output_size;
  memcpy(ctx->receipt.return_data, res.output_data, res.output_size);
  debug_print_int("status_code", res.status_code);
  ckb_debug("END handle_message");
  return (int)res.status_code;
}
