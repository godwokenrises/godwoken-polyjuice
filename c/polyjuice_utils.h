#ifndef POLYJUICE_UTILS_H
#define POLYJUICE_UTILS_H

#include <stddef.h>
#include <stdint.h>

#include <evmc/evmc.h>
#include "ckb_syscalls.h"
#include "polyjuice_globals.h"
#include "polyjuice_errors.h"

#ifdef CKB_C_STDLIB_PRINTF
/* 64 KB */
#define DEBUG_BUFFER_SIZE 65536
static char *g_debug_buffer;
void debug_print_data(const char *prefix, const uint8_t *data,
                      uint32_t data_len) {
  if (data_len > (DEBUG_BUFFER_SIZE - 1024) / 2 - 1) { // leave 1KB to prefix
    ckb_debug("warning: length of data is too large");
    return;
  }

  int offset = 0;
  offset += sprintf(g_debug_buffer, "%s 0x", prefix);
  if (offset > 1024) {
    ckb_debug("warning: length of prefix is too large");
    return;
  }
  for (size_t i = 0; i < data_len; i++) {
    offset += sprintf(g_debug_buffer + offset, "%02x", data[i]);
  }
  g_debug_buffer[offset] = '\0';
  ckb_debug(g_debug_buffer);
}
void debug_print_int(const char* prefix, int64_t ret) {
  sprintf(g_debug_buffer, "%s => %ld", prefix, ret);
  ckb_debug(g_debug_buffer);
}
#else
#undef ckb_debug
#define ckb_debug(s) do {} while (0)
#define debug_print(s) do {} while (0)
#define debug_print_int(prefix, value) do {} while (0)
#define debug_print_data(prefix, data, data_len) do {} while (0)
int printf(const char *format, ...) { return 0; }
#endif /* CKB_C_STDLIB_PRINTF */

#define memset(dest, c, n) _smt_fast_memset(dest, c, n)

/* https://stackoverflow.com/a/1545079 */
#pragma push_macro("errno")
#undef errno
bool is_errno_ok(mol_seg_res_t *script_res) {
  return script_res->errno == MOL_OK;
}
#pragma pop_macro("errno")

int build_script(const uint8_t code_hash[32], const uint8_t hash_type,
                 const uint8_t* args, const uint32_t args_len,
                 mol_seg_t* script_seg) {
  /* 1. Build Script by receipt.return_data */
  mol_seg_t args_seg;
  args_seg.size = 4 + args_len;
  args_seg.ptr = (uint8_t*)malloc(args_seg.size);
  if (args_seg.ptr == NULL) {
    return FATAL_POLYJUICE;
  }
  memcpy(args_seg.ptr, (uint8_t*)(&args_len), 4);
  memcpy(args_seg.ptr + 4, args, args_len);
  debug_print_int("script.hash_type", hash_type);

  mol_builder_t script_builder;
  MolBuilder_Script_init(&script_builder);
  MolBuilder_Script_set_code_hash(&script_builder, code_hash, 32);
  MolBuilder_Script_set_hash_type(&script_builder, hash_type);
  MolBuilder_Script_set_args(&script_builder, args_seg.ptr, args_seg.size);
  mol_seg_res_t script_res = MolBuilder_Script_build(script_builder);
  free(args_seg.ptr);

  if (!is_errno_ok(&script_res)) {
    ckb_debug("molecule build script failed");
    return FATAL_POLYJUICE;
  }

  *script_seg = script_res.seg;
  if (MolReader_Script_verify(script_seg, false) != MOL_OK) {
    ckb_debug("built an invalid script");
    return FATAL_POLYJUICE;
  }
  return 0;
}

/**
 * @param address eth_address of a contract account is also short_script_hash
 */
int short_script_hash_to_account_id(gw_context_t *ctx,
                                    const uint8_t address[20],
                                    uint32_t *account_id) {
  uint8_t script_hash[32] = {0};
  int ret = ctx->sys_get_script_hash_by_prefix(ctx, (uint8_t *)address, 20,
                                               script_hash);
  if (ret != 0) {
    return ret;
  }
  return ctx->sys_get_account_id_by_script_hash(ctx, script_hash, account_id);
}

void gw_build_script_hash_to_eth_address_key(
    const uint8_t script_hash[GW_KEY_BYTES], uint8_t raw_key[GW_KEY_BYTES]) {
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, GW_KEY_BYTES);
  uint32_t placeholder = 0;
  blake2b_update(&blake2b_ctx, (uint8_t *)&placeholder, sizeof(uint32_t));
  uint8_t type = GW_ACCOUNT_SCRIPT_HASH_TO_ETH_ADDRESS;
  blake2b_update(&blake2b_ctx, (uint8_t *)&type, 1);
  blake2b_update(&blake2b_ctx, script_hash, GW_KEY_BYTES);
  blake2b_final(&blake2b_ctx, raw_key, GW_KEY_BYTES);
}

void gw_build_eth_address_to_script_hash_key(
    const uint8_t eth_address[ETH_ADDRESS_LEN], uint8_t raw_key[GW_KEY_BYTES]) {
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, GW_KEY_BYTES);
  /* placeholder: 0 */
  uint32_t placeholder = 0;
  blake2b_update(&blake2b_ctx, (uint8_t *)&placeholder, sizeof(uint32_t));
  /* type */
  uint8_t type = GW_ETH_ADDRESS_TO_ACCOUNT_SCRIPT_HASH;
  blake2b_update(&blake2b_ctx, (uint8_t *)&type, 1);
  /* eth_address */
  blake2b_update(&blake2b_ctx, eth_address, ETH_ADDRESS_LEN);
  blake2b_final(&blake2b_ctx, raw_key, GW_KEY_BYTES);
}

/**
 * @param script_hash should have been initialed as zero_hash = {0}
 */
int load_script_hash_by_eth_address(gw_context_t *ctx,
                                    const uint8_t eth_address[ETH_ADDRESS_LEN],
                                    uint8_t script_hash[GW_VALUE_BYTES]) {                                    
  if (ctx == NULL) {
    return GW_FATAL_INVALID_CONTEXT;
  }

  uint8_t raw_key[GW_KEY_BYTES] = {0};
  gw_build_eth_address_to_script_hash_key(eth_address, raw_key);

  int ret = ctx->_internal_load_raw(ctx, raw_key, script_hash);
  if (ret != 0) {
    return ret;
  }

  // not found in `ETH Address Registry`, means that it is not an EOA.
  if (_is_zero_hash(script_hash)) { 
    // maybe it is a Polyjuice Contract Account
    ret = ctx->sys_get_script_hash_by_prefix(ctx, eth_address,
                                             DEFAULT_SHORT_SCRIPT_HASH_LEN,
                                             script_hash);
    if (ret != 0) {
      return GW_ERROR_NOT_FOUND;
    }
  }

  // TODO: shall we cache [eth_address <=> script_hash] mapping data?
  return 0;
}

int load_eth_address_by_script_hash(gw_context_t *ctx,
                                    const uint8_t script_hash[GW_KEY_BYTES],
                                    uint8_t eth_address[ETH_ADDRESS_LEN]) {
  if (ctx == NULL) {
    return GW_FATAL_INVALID_CONTEXT;
  }

  uint8_t raw_key[GW_KEY_BYTES] = {0};
  gw_build_script_hash_to_eth_address_key(script_hash, raw_key);

  /** 
   * ethabi address format
   *  e.g. web3.eth.abi.decodeParameter('address',
   *         '0000000000000000000000001829d79cce6aa43d13e67216b355e81a7fffb220')
   */
  uint8_t value[GW_VALUE_BYTES] = {0};
  int ret = ctx->_internal_load_raw(ctx, raw_key, value);
  if (ret != 0) {
    return ret;
  }
  if (_is_zero_hash(value)) {
    return GW_ERROR_NOT_FOUND;
  }

  _gw_fast_memcpy(eth_address, value + 12, ETH_ADDRESS_LEN);
  return 0;
}

int update_eth_address_registry(gw_context_t *ctx,
                                const uint8_t eth_address[ETH_ADDRESS_LEN],
                                const uint8_t script_hash[GW_VALUE_BYTES]) {
  debug_print_data("[eth_address_registry] update eth_address",
                     eth_address, ETH_ADDRESS_LEN);
  debug_print_data("[eth_address_registry] update godwoken_account_script_hash",
                     script_hash, GW_VALUE_BYTES);

  if (ctx == NULL) {
    return GW_FATAL_INVALID_CONTEXT;
  }
  int ret;
  uint8_t raw_key[GW_KEY_BYTES];

  // eth_address -> gw_script_hash
  gw_build_eth_address_to_script_hash_key(eth_address, raw_key);
  ret = ctx->_internal_store_raw(ctx, raw_key, script_hash);
  if (ret != 0) {
    return ret;
  }

  // gw_script_hash -> eth_address
  gw_build_script_hash_to_eth_address_key(script_hash, raw_key);
  /** 
   * ethabi address format
   *  e.g. web3.eth.abi.decodeParameter('address',
   *         '0000000000000000000000001829d79cce6aa43d13e67216b355e81a7fffb220')
   */
  uint8_t value[GW_VALUE_BYTES] = {0};
  _gw_fast_memcpy(value + 12, eth_address, ETH_ADDRESS_LEN);
  ret = ctx->_internal_store_raw(ctx, raw_key, value);
  if (ret != 0) {
    return ret;
  }

  ckb_debug("[eth_address_registry] set mapping finished");
  return 0;
}

/**
 * @brief register an account into `ETH Address Registry` by it's script_hash
 * 
 * @param ctx 
 * @param script_hash 
 * @return int 
 */
int eth_address_register(gw_context_t *ctx,
                         uint8_t script_hash[GW_VALUE_BYTES]) {
  debug_print_data("[eth_address_registry] new mapping for account_script_hash",
                   script_hash, GW_VALUE_BYTES);
  if (ctx == NULL) {
    return GW_FATAL_INVALID_CONTEXT;
  }
  int ret;

  // check account existence
  uint32_t account_id;
  ret = ctx->sys_get_account_id_by_script_hash(ctx, script_hash, &account_id);
  if (ret != 0) {
    debug_print_int("[eth_address_registry] account not found", ret);
    return GW_ERROR_ACCOUNT_NOT_EXISTS;
  }

  // get the script of the account
  uint8_t script_buffer[GW_MAX_SCRIPT_SIZE];
  uint64_t script_len = GW_MAX_SCRIPT_SIZE;
  ret = ctx->sys_get_account_script(ctx, account_id, &script_len, 0,
                                    script_buffer);
  if (ret != 0) {
    debug_print_int("[eth_address_registry] get_account_script failed", ret);
    return ret;
  }
  mol_seg_t script_seg;
  script_seg.ptr = script_buffer;
  script_seg.size = script_len;
  if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
    // TODO: maybe we don't need to verify script,
    // since it is a Script of an existing Godwoken account
    return GW_ERROR_INVALID_ACCOUNT_SCRIPT;
  }
  mol_seg_t script_code_hash_seg = MolReader_Script_get_code_hash(&script_seg);

  // get rollup_config to compare with
  mol_seg_t rollup_config_seg;
  rollup_config_seg.ptr = ctx->rollup_config;
  rollup_config_seg.size = ctx->rollup_config_size;
  uint8_t eth_address[ETH_ADDRESS_LEN];

  // Option 1: EOA account with native eth_address
  mol_seg_t allowed_eoa_list_seg =
      MolReader_RollupConfig_get_allowed_eoa_type_hashes(&rollup_config_seg);
  const uint32_t eth_eoa_idx = 0;
  mol_seg_res_t eth_lock_code_hash_res =
      MolReader_Byte32Vec_get(&allowed_eoa_list_seg, eth_eoa_idx);
  if (!is_errno_ok(&eth_lock_code_hash_res)) {
    ckb_debug("[eth_address_registry] failed to get eth_lock EOA code_hash");
    return GW_FATAL_INVALID_DATA;
  }
  if (memcmp(script_code_hash_seg.ptr, eth_lock_code_hash_res.seg.ptr, 
             script_code_hash_seg.size) == 0) {
    ckb_debug("[eth_address_registry] EOA account with native eth_address");
    mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
    mol_seg_t raw_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
    if (raw_bytes_seg.size != 52 ) {
      ckb_debug("[eth_address_registry] not eth_account_lock");
      return GW_FATAL_UNKNOWN_ARGS;
    }
    _gw_fast_memcpy(eth_address, raw_bytes_seg.ptr + 32, ETH_ADDRESS_LEN);
    return update_eth_address_registry(ctx, eth_address, script_hash);
  }

  // Option 2: Polyjuice Contract Account
  // NOTICE: We should avoid address conflict between
  //         `eth_native_address` and `short_godwoken_account_script_hash`
  mol_seg_t allowed_contract_list_seg =
      MolReader_RollupConfig_get_allowed_contract_type_hashes(&rollup_config_seg);
  const uint32_t polyjuice_idx = 2;
  mol_seg_res_t polyjuice_code_hash_res =
      MolReader_Byte32Vec_get(&allowed_contract_list_seg, polyjuice_idx);
  if (!is_errno_ok(&polyjuice_code_hash_res)) {
    ckb_debug("[eth_address_registry] failed to get Polyjuice code_hash");
    return GW_FATAL_INVALID_DATA;
  }
  if (memcmp(script_code_hash_seg.ptr, polyjuice_code_hash_res.seg.ptr,
             script_code_hash_seg.size) == 0) {
    // In this situation, "eth_address" is short_godwoken_account_script_hash.
    ckb_debug("[eth_address_registry] Polyjuice contract account");

    // Only set mapping from `gw_script_hash` to "eth_address"
    // to avoid address conflict.
    uint8_t raw_key[GW_KEY_BYTES];
    gw_build_script_hash_to_eth_address_key(script_hash, raw_key);
    /** 
     * ethabi address format
     *  e.g. web3.eth.abi.decodeParameter('address',
     *         '0000000000000000000000001829d79cce6aa43d13e67216b355e81a7fffb220')
     */
    uint8_t value[GW_VALUE_BYTES] = {0};
    _gw_fast_memcpy(value + 12, script_hash, ETH_ADDRESS_LEN);
    return ctx->_internal_store_raw(ctx, raw_key, value);
  }

  // TODO: check selfdestruct?

  return GW_ERROR_UNKNOWN_SCRIPT_CODE_HASH;
}

/**
 * @brief 
 * TODO: test this function
 * @param ctx 
 * @param address 
 * @param account_id 
 * @return int 
 */
// int load_account_id_by_eth_address(gw_context_t *ctx,
//                               const uint8_t address[20],
//                               uint32_t *account_id) {
//   if (ctx == NULL) {
//     return GW_FATAL_INVALID_CONTEXT;
//   }
//   uint8_t script_hash[32] = {0};
//   int ret = load_script_hash_by_eth_address(ctx, address, script_hash);
//   if (ret != 0) {
//     debug_print_int("load_script_hash_by_eth_address failed", ret);
//     return ret;
//   }
//   return ctx->sys_get_account_id_by_script_hash(ctx, script_hash, account_id);
// }

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

/* Parse uint32_t/uint128_t from big endian byte32 data */
int parse_integer(const uint8_t data_be[32], uint8_t *value, size_t value_size) {
  if (value_size > 32) {
    return -1;
  }
  /* Check leading zeros */
  for (size_t i = 0; i < (32 - value_size); i++) {
    if (data_be[i] != 0) {
      return -1;
    }
  }

  for (size_t i = 0; i < value_size; i++) {
    value[i] = data_be[31 - i];
  }
  return 0;
}

int parse_u32(const uint8_t data_be[32], uint32_t *value) {
  return parse_integer(data_be, (uint8_t *)value, sizeof(uint32_t));
}
int parse_u64(const uint8_t data_be[32], uint64_t *value) {
  return parse_integer(data_be, (uint8_t *)value, sizeof(uint64_t));
}
int parse_u128(const uint8_t data_be[32], uint128_t *value) {
  return parse_integer(data_be, (uint8_t *)value, sizeof(uint128_t));
}

/* serialize uint64_t to big endian byte32 */
void put_u64(uint64_t value, uint8_t *output) {
  uint8_t *value_le = (uint8_t *)(&value);
  for (size_t i = 0; i < 8; i++) {
    *(output + 31 - i) = *(value_le + i);
  }
}

/* serialize uint128_t to big endian byte32 */
void put_u128(uint128_t value, uint8_t *output) {
  uint8_t *value_le = (uint8_t *)(&value);
  for (size_t i = 0; i < 16; i++) {
    *(output + 31 - i) = *(value_le + i);
  }
}

/* If it is a fatal error, terminate the whole process.
 * ====
 *   - gw_errors.h           GW_FATAIL_xxx               [50, 80)
 *   - polyjuice_globals.h   FATAL_POLYJUICE             -50
 *   - polyjuice_globals.h   FATAL_PRECOMPILED_CONTRACTS -51
 */
bool is_fatal_error(int error_code) {
  return (error_code >= 50 && error_code < 80) || (error_code > -80 && error_code <= -50);
}

/* See evmc.h evmc_status_code */
bool is_evmc_error(int error_code) {
  return error_code >= 1 && error_code <= 16;
}

#endif // POLYJUICE_UTILS_H
