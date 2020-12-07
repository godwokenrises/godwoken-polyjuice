#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "gw_def.h"
#include "common.h"
#include "godwoken.h"
#include "ckb_syscalls.h"

#include <map>
#include <iterator>
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

int gw_construct(gw_context_t * ctx);
int gw_handle_message(gw_context_t* ctx);

struct evmc_host_context {
  gw_context_t* gw_ctx;
  evmc_address tx_origin;
  int error_code;
  mol_seg_t script_seg;
  void *mock_map;
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

  /* FIXME: Check from_id and to_id code hash, ONLY ALLOW: [polyjuice, sudt] */
  evmc_address sender;
  evmc_address destination;
  debug_print_int("get script hash of from account: ", ctx->call_context.from_id);
  memcpy(sender.bytes, (uint8_t *)(&ctx->call_context.from_id), 4);
  debug_print_data("sender", sender.bytes, 20);
  if (msg->kind == EVMC_CREATE) {
    debug_print_int("get script hash of to account: ", ctx->call_context.to_id);
    memcpy(destination.bytes, (uint8_t *)(&ctx->call_context.to_id), 4);
    debug_print_data("destination", destination.bytes, 20);
  } else {
    memset(destination.bytes, 0, 20);
  }

  debug_print_int("args_len", ctx->call_context.args_len);
  /* == Args decoder */
  uint8_t *args = ctx->call_context.args;
  size_t tx_origin_len = 0;
  /* args[0..2] */
  uint32_t depth = (uint32_t)(*(uint16_t *)args);
  debug_print_int("depth", depth);
  if (depth > 0) {
    tx_origin_len = 20;
  }
  /* args[2..3] */
  uint8_t flags = *(args + 2 + tx_origin_len);
  debug_print_int("flags", flags);
  /* args[3..35] */
  evmc_uint256be value = *((evmc_uint256be *)(args + 2 + tx_origin_len + 1));
  debug_print_data("value", value.bytes, 32);
  /* args[35..39] */
  uint32_t input_size = *((uint32_t *)(args + 2 + tx_origin_len + 1 + 32));
  debug_print_int("input_size", input_size);
  /* args[39..39+input_size] */
  uint8_t *input_data = args + 2 + tx_origin_len + 1 + 32 + 4;
  debug_print_data("input_data", input_data, input_size);

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
  if (context->mock_map != NULL) {
    std::map<evmc::bytes32, evmc::bytes32> *mock_map = (std::map<evmc::bytes32, evmc::bytes32> *)context->mock_map;
    auto it = mock_map->find((evmc::bytes32)(*key));
    if (it != mock_map->end()) {
      memcpy(value.bytes, it->second.bytes, 32);
      return value;
    }
  }

  int ret = context->gw_ctx->sys_load((void *)context->gw_ctx,
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
  if (context->mock_map != NULL) {
    std::map<evmc::bytes32, evmc::bytes32> *mock_map = (std::map<evmc::bytes32, evmc::bytes32> *)context->mock_map;
    mock_map->insert(std::pair<evmc::bytes32, evmc::bytes32>((evmc::bytes32)(*key), (evmc::bytes32)(*value)));
  } else {
    int ret = context->gw_ctx->sys_store((void *)context->gw_ctx, key->bytes, value->bytes);
    if (ret != 0) {
      context->error_code = ret;
    }
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

  /* prepare context */
  uint32_t from_id = gw_ctx->call_context.to_id;
  gw_call_receipt_t receipt;
  gw_context_t sub_gw_ctx;
  receipt.return_data_len = 0;
  ret = gw_create_sub_context(gw_ctx, &sub_gw_ctx, from_id, to_id, args, args_len);
  sub_gw_ctx.sys_context = &receipt;
  if (ret != 0) {
    context->error_code = ret;
    res.status_code = EVMC_REVERT;
    return res;
  }

  /* TODO: handle special kind (CREATE2/CALLCODE/DELEGATECALL)*/
  if (msg->kind == EVMC_CALL) {
    ret = gw_handle_message(&sub_gw_ctx);
    memset(res.create_address.bytes, 0, 20);
  } else if (msg->kind == EVMC_CREATE) {
    /* assert(to_id == 0) */
    if (to_id != 0) {
      context->error_code = ret;
      res.status_code = EVMC_REVERT;
      return res;
    }

    ret = gw_construct(&sub_gw_ctx);
    if (ret != 0) {
      context->error_code = ret;
      res.status_code = EVMC_REVERT;
      return res;
    }

    /* 1. Build Script by receipt.return_data */
    mol_seg_t code_hash_seg = MolReader_Script_get_code_hash(&context->script_seg);
    mol_seg_t hash_type_seg = MolReader_Script_get_hash_type(&context->script_seg);
    mol_seg_t args_seg;
    args_seg.size = 4 + receipt.return_data_len;
    args_seg.ptr = (uint8_t *)malloc(args_seg.size);
    memcpy(args_seg.ptr, (uint8_t *)(&receipt.return_data_len), 4);
    memcpy(args_seg.ptr + 4, receipt.return_data, receipt.return_data_len);

    mol_builder_t script_builder;
    MolBuilder_Script_init(&script_builder);
    MolBuilder_Script_set_code_hash(&script_builder, code_hash_seg.ptr, code_hash_seg.size);
    MolBuilder_Script_set_hash_type(&script_builder, *hash_type_seg.ptr);
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
    ret = gw_ctx->sys_create((void *)gw_ctx, new_script_seg.ptr, new_script_seg.size, &receipt);
    if (ret != 0) {
      context->error_code = ret;
      res.status_code = EVMC_REVERT;
      return res;
    }

    /* 3. Get account id by script hash */
    uint8_t new_script_hash[32];
    blake2b_state blake2b_ctx;
    blake2b_init(&blake2b_ctx, 32);
    blake2b_update(&blake2b_ctx, new_script_seg.ptr, new_script_seg.size);
    blake2b_final(&blake2b_ctx, new_script_hash, 32);
    uint32_t new_account_id;
    ret = gw_ctx->sys_get_account_id_by_script_hash((void *)gw_ctx, new_script_hash, &new_account_id);
    if (ret != 0) {
      context->error_code = ret;
      res.status_code = EVMC_REVERT;
      return res;
    }

    /* 4. Set account id to sub_gw_ctx.call_context.to_id */
    sub_gw_ctx.call_context.to_id = new_account_id;

    /* 5. Set res.create_address by sub_gw_ctx.call_context.to_id */
    res.create_address = account_id_to_address(sub_gw_ctx.call_context.to_id);
  } else {
    /* ERROR: Invalid call kind */
    context->error_code = -1;
    res.status_code = EVMC_REVERT;
    return res;
  }
  /* Free the buffer after use sub_gw_ctx.call_context.args */
  free(sub_gw_ctx.call_context.args);
  sub_gw_ctx.call_context.args = NULL;

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
  int ret = context->gw_ctx->sys_log((void *)context->gw_ctx, (uint32_t) output_size, output);
  if (ret != 0) {
    context->error_code = ret;
  }
  free(output);
  ckb_debug("END emit_log");
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
    memcpy(tx_origin.bytes, ctx->call_context.args + 1, 20);
  }
  mol_seg_t script_seg;
  uint8_t *code_data = NULL;
  size_t code_size = 0;
  ret = load_account_code(ctx, ctx->call_context.to_id, &script_seg, &code_data, &code_size);
  if (ret != 0) {
    return ret;
  }
  void *mock_map = NULL;
  if (ctx->call_context.to_id == 0) {
    std::map<evmc::bytes32, evmc::bytes32> kv_map;
    mock_map = (void*)&kv_map;
  }
  struct evmc_host_context context { ctx, tx_origin, 0, script_seg, mock_map };

  const uint8_t *current_code_data = msg.input_data;
  size_t current_code_size = msg.input_size;
  msg.input_data = NULL;
  msg.input_size = 0;

  ckb_debug("BEGIN vm->execute()");
  struct evmc_result res = vm->execute(vm, &interface, &context, EVMC_MAX_REVISION, &msg, current_code_data, current_code_size);
  ckb_debug("END vm->execute()");
  if (context.error_code != 0)  {
    return context.error_code;
  }
  /* FIXME: handle created address */

  if (ctx->call_context.to_id != 0) {
    /* Check res.output_data == code */
    if (code_size != res.output_size) {
      /* ERROR: return data length not match the script args length */
      return -1;
    }
    if (memcmp(code_data, res.output_data, code_size)) {
      /* ERROR: return data not match the script data */
      return -1;
    }
  }
  ckb_debug("BEGIN: free loaded code data");
  free((void *)script_seg.ptr);
  ckb_debug("END: free loaded code data");

  gw_call_receipt_t *receipt = (gw_call_receipt_t *)ctx->sys_context;
  debug_print_int("output size", res.output_size);
  receipt->return_data_len = (uint32_t)res.output_size;
  memcpy(receipt->return_data, res.output_data, res.output_size);
  ckb_debug("END gw_construct");
  debug_print_int("status_code", res.status_code);
  return (int)res.status_code;
}

/* parse args then call contract */
int gw_handle_message(gw_context_t* ctx) {
  ckb_debug("BEGIN gw_handle_message");
  int ret;
  struct evmc_message msg;
  ckb_debug("BEGIN init_message()");
  ret = init_message(&msg, ctx);
  ckb_debug("END init_message()");
  if (ret != 0) {
    return ret;
  }
  if (msg.kind != EVMC_CALL) {
    /* TODO: Invalid call type or NOT supported yet */
    return -1;
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
    memcpy(tx_origin.bytes, ctx->call_context.args + 1, 20);
  }
  mol_seg_t script_seg;
  uint8_t *code_data = NULL;
  size_t code_size = 0;
  ret = load_account_code(ctx, ctx->call_context.to_id, &script_seg, &code_data, &code_size);
  if (ret != 0) {
    return ret;
  }
  struct evmc_host_context context { ctx, tx_origin, 0, script_seg, NULL };

  struct evmc_result res = vm->execute(vm, &interface, &context, EVMC_MAX_REVISION, &msg, code_data, code_size);
  free((void *)script_seg.ptr);
  if (context.error_code != 0)  {
    return context.error_code;
  }

  gw_call_receipt_t *receipt = (gw_call_receipt_t *)ctx->sys_context;
  debug_print_int("output size", res.output_size);
  receipt->return_data_len = (uint32_t)res.output_size;
  memcpy(receipt->return_data, res.output_data, res.output_size);
  debug_print_int("status_code", res.status_code);
  ckb_debug("END gw_handle_message");
  return (int)res.status_code;
}

int gw_polyjuice_construct(gw_context_t * ctx) {
  return gw_construct(ctx);
}
int gw_polyjuice_handle_message(gw_context_t* ctx) {
  return gw_handle_message(ctx);
}
