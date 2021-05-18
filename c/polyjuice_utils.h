
#ifndef POLYJUICE_UTILS_H
#define POLYJUICE_UTILS_H

#include <stddef.h>
#include <stdint.h>

#include <evmc/evmc.h>
#include "ckb_syscalls.h"

#ifdef NO_DEBUG_LOG
#undef ckb_debug
#define ckb_debug(s) {}
#define debug_print(s) {}
#define debug_print_int(prefix, value) {}
#define debug_print_data(prefix, data, data_len) {}
#else  /* #ifdef NO_DEBUG_LOG */
static char debug_buffer[64 * 1024];
void debug_print_data(const char* prefix, const uint8_t* data,
                             uint32_t data_len) {
  int offset = 0;
  offset += sprintf(debug_buffer, "%s 0x", prefix);
  for (size_t i = 0; i < data_len; i++) {
    offset += sprintf(debug_buffer + offset, "%02x", data[i]);
  }
  debug_buffer[offset] = '\0';
  ckb_debug(debug_buffer);
}
void debug_print_int(const char* prefix, int64_t ret) {
  sprintf(debug_buffer, "%s => %ld", prefix, ret);
  ckb_debug(debug_buffer);
}
#endif  /* #ifdef NO_DEBUG_LOG */

/* polyjuice contract account (normal/create2) script args size*/
static const uint32_t CONTRACT_ACCOUNT_SCRIPT_ARGS_SIZE = 32 + 4 + 20;

/*
  eth_address[ 0..16] = script_hash[0..16]
  eth_address[16..20] = account_id (little endian)
 */
int account_id_to_address(gw_context_t* ctx, uint32_t account_id, evmc_address *addr) {
  if (account_id == 0) {
    memset(addr->bytes, 0, 20);
    return 0;
  }

  uint8_t script_hash[32] = {0};
  int ret = ctx->sys_get_script_hash_by_account_id(ctx, account_id, script_hash);
  if (ret != 0) {
    debug_print_int("get script hash by account id failed", account_id);
    return ret;
  }

  memcpy(addr->bytes, script_hash, 16);
  memcpy(addr->bytes + 16, (uint8_t*)(&account_id), 4);
  return 0;
}

/*
  Must check eth_address[0..16] match the script_hash[0..16] of the account id
 */
int address_to_account_id(gw_context_t* ctx, const evmc_address* address, uint32_t* account_id) {
  /* Zero address is special case */
  static uint8_t zero_address[20] = {0};
  if (memcmp(address->bytes, zero_address, 20) == 0) {
    *account_id = 0;
    return 0;
  }

  *account_id = *((uint32_t*)(address->bytes + 16));
  uint8_t script_hash[32] = {0};
  int ret = ctx->sys_get_script_hash_by_account_id(ctx, *account_id, script_hash);
  if (ret != 0) {
    debug_print_int("get script hash by account id failed", *account_id);
    return ret;
  }
  bool exists = false;
  for (int i = 0; i < 32; i++) {
    /* if account not exists script_hash will be zero */
    if (script_hash[i] != 0) {
      exists = true;
      break;
    }
  }
  if (!exists) {
    debug_print_int("script hash not exists by account id", *account_id);
    return -1;
  }
  if (memcmp(address->bytes, script_hash, 16) != 0) {
    debug_print_data("check script hash failed, invalid eth address", address->bytes, 20);
    return -1;
  }
  return 0;
}

int build_script(const uint8_t code_hash[32], const uint8_t hash_type,
                 const uint8_t* args, const uint32_t args_len,
                 mol_seg_t* script_seg) {
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

int get_contract_account_id(gw_context_t* ctx,
                            const uint8_t script_code_hash[32],
                            const uint8_t script_hash_type,
                            const uint8_t rollup_script_hash[32],
                            const uint32_t creator_account_id,
                            const uint8_t eth_address[20],
                            uint32_t *account_id) {
  int ret;
  uint8_t args[CONTRACT_ACCOUNT_SCRIPT_ARGS_SIZE] = {0};
  memcpy(args, rollup_script_hash, 32);
  memcpy(args + 32, (uint8_t *)(&creator_account_id), 4);
  memcpy(args + 32 + 4, eth_address, 20);

  mol_seg_t new_script_seg;
  ret = build_script(script_code_hash, script_hash_type, args, CONTRACT_ACCOUNT_SCRIPT_ARGS_SIZE, &new_script_seg);
  if (ret != 0) {
    return ret;
  }
  uint8_t script_hash[32] = {0};
  blake2b_hash(script_hash, new_script_seg.ptr, new_script_seg.size);
  free(new_script_seg.ptr);
  ret = ctx->sys_get_account_id_by_script_hash(ctx, script_hash, account_id);
  if (ret != 0) {
    return ret;
  }
  return 0;
}

void rlp_encode_sender_and_nonce(const evmc_address *sender, uint32_t nonce,
                                 uint8_t *data, uint32_t *data_len) {
  static const uint8_t RLP_ITEM_OFFSET = 0x80;
  static const uint8_t RLP_LIST_OFFSET = 0xc0;

  uint8_t *nonce_le = (uint8_t *)(&nonce);
  uint8_t nonce_be[4] = {0};
  nonce_be[0] = nonce_le[3];
  nonce_be[1] = nonce_le[2];
  nonce_be[2] = nonce_le[1];
  nonce_be[3] = nonce_le[0];
  uint32_t nonce_bytes_len = 0;
  for (size_t i = 0; i < 4; i++) {
    if (nonce_be[i] != 0) {
      nonce_bytes_len = 4 - i;
      break;
    }
  }

  /* == RLP encode == */
  /* sender header */
  data[1] = 20 + RLP_ITEM_OFFSET;
  /* sender content */
  memcpy(data + 2, sender->bytes, 20);
  if (nonce_bytes_len == 1 && nonce_be[3] < RLP_ITEM_OFFSET) {
    data[2 + 20] = nonce_be[3];
    *data_len = 2 + 20 + 1;
  } else {
    /* nonce header */
    data[2 + 20] = nonce_bytes_len + RLP_ITEM_OFFSET;
    /* nonce content */
    memcpy(data + 2 + 20 + 1, nonce_be + (4 - nonce_bytes_len), nonce_bytes_len);
    *data_len = 2 + 20 + 1 + nonce_bytes_len;
  }
  /* list header */
  data[0] = *data_len - 1 + RLP_LIST_OFFSET;
}

#endif // POLYJUICE_UTILS_H
