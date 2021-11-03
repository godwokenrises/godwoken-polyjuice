
#ifndef POLYJUICE_UTILS_H
#define POLYJUICE_UTILS_H

#include <stddef.h>
#include <stdint.h>

#include <evmc/evmc.h>
#include "ckb_syscalls.h"
#include "polyjuice_errors.h"

#define ETH_ADDRESS_LEN 20
#define GW_ETH_ADDRESS_TO_ACCOUNT_SCRIPT_HASH 6
#define GW_ACCOUNT_SCRIPT_HASH_TO_ETH_ADDRESS 7

#ifdef NO_DEBUG_LOG
#undef ckb_debug
#define ckb_debug(s) do {} while (0)
#define debug_print(s) do {} while (0)
#define debug_print_int(prefix, value) do {} while (0)
#define debug_print_data(prefix, data, data_len) do {} while (0)
#else /* NO_DEBUG_LOG */
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
#endif /* NO_DEBUG_LOG */

#define memset(dest, c, n) _smt_fast_memset(dest, c, n)

/* polyjuice contract account (normal/create2) script args size*/
static const uint32_t CONTRACT_ACCOUNT_SCRIPT_ARGS_SIZE = 32 + 4 + 20;

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

  /* https://stackoverflow.com/a/1545079 */
#pragma push_macro("errno")
#undef errno
  if (script_res.errno != MOL_OK) {
    ckb_debug("molecule build script failed");
    return FATAL_POLYJUICE;
  }
#pragma pop_macro("errno")

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

void gw_build_script_hash_to_eth_address_key(uint8_t script_hash[GW_KEY_BYTES],
                                             uint8_t raw_key[GW_KEY_BYTES]) {
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

  if (_is_zero_hash(script_hash)) {
    return GW_ERROR_NOT_FOUND;
  }

  // TODO: cache [eth_address <=> script_hash] mapping data here
  return 0;
}

int load_eth_address_by_script_hash(gw_context_t *ctx,
                                    uint8_t script_hash[GW_KEY_BYTES],
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
