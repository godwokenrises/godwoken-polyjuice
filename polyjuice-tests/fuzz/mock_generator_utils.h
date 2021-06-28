#ifndef GW_GENERATOR_H_
#define GW_GENERATOR_H_

/* Layer2 contract generator
 *
 * The generator supposed to be run off-chain.
 * generator dynamic linking with the layer2 contract code,
 * and provides layer2 syscalls.
 *
 * A program should be able to generate a post state after run the generator,
 * and should be able to use the states to construct a transaction that satifies
 * the validator.
 */

#include "ckb_syscalls.h"
#include "common.h"

#include "secp256k1_data_info.h"
#include "mock_godwoken.hpp"

/* syscalls */
/* Syscall account store / load / create */
#define GW_SYS_CREATE 3100
#define GW_SYS_STORE 3101
#define GW_SYS_LOAD 3102
#define GW_SYS_LOAD_SCRIPT_HASH_BY_ACCOUNT_ID 3103
#define GW_SYS_LOAD_ACCOUNT_ID_BY_SCRIPT_HASH 3104
#define GW_SYS_LOAD_ACCOUNT_SCRIPT 3105
#define GW_SYS_GET_SCRIPT_HASH_BY_SHORT_ADDRESS 3106
/* Syscall call / return */
#define GW_SYS_SET_RETURN_DATA 3201
/* Syscall data store / load */
#define GW_SYS_STORE_DATA 3301
#define GW_SYS_LOAD_DATA 3302
/* Syscall load metadata structures */
#define GW_SYS_LOAD_ROLLUP_CONFIG 3401
#define GW_SYS_LOAD_TRANSACTION 3402
#define GW_SYS_LOAD_BLOCKINFO 3403
#define GW_SYS_GET_BLOCK_HASH 3404
/* Syscall builtins */
#define GW_SYS_PAY_FEE 3501
#define GW_SYS_LOG 3502
#define GW_SYS_RECOVER_ACCOUNT 3503

/* Godwoken Service Flag */
// #define GW_LOG_SUDT_TRANSFER    0
// #define GW_LOG_SUDT_PAY_FEE     1
// #define GW_LOG_POLYJUICE_SYSTEM 2
// #define GW_LOG_POLYJUICE_USER   3

#define MOCK_SUCCESS 0
#define MOCK_SECP256K1_ERROR_LOADING_DATA -101

// FIXME read script_hash from mock State+CodeStore
static const uint8_t test_script_hash[6][32] = {
  {231, 196, 69, 164, 212, 229, 83, 6, 137, 240, 237, 105, 234, 223, 101, 133, 197, 66, 85, 214, 112, 85, 87, 71, 17, 170, 138, 126, 128, 173, 186, 76},
  {50, 15, 9, 23, 166, 82, 42, 69, 226, 148, 203, 184, 168, 8, 210, 62, 226, 187, 187, 21, 122, 141, 152, 55, 88, 230, 63, 204, 23, 3, 166, 102},
  {221, 60, 233, 16, 227, 19, 49, 118, 137, 43, 193, 160, 145, 21, 141, 6, 43, 206, 191, 210, 105, 160, 112, 23, 155, 184, 101, 113, 47, 247, 216, 122},
  {48, 160, 141, 250, 92, 214, 34, 124, 231, 78, 106, 179, 173, 80, 61, 55, 161, 156, 45, 114, 214, 222, 9, 77, 4, 104, 52, 44, 30, 149, 27, 36},
  {103, 167, 175, 25, 71, 242, 5, 31, 102, 236, 38, 188, 223, 212, 241, 99, 13, 4, 40, 150, 151, 55, 40, 147, 64, 29, 108, 50, 37, 159, 55, 137},
  {125, 181, 86, 185, 69, 172, 188, 175, 36, 25, 118, 119, 114, 72, 199, 183, 204, 25, 147, 120, 109, 220, 192, 171, 10, 235, 47, 230, 42, 210, 169, 223}};

typedef struct gw_context_t {
  /* verification context */
  gw_transaction_context_t transaction_context;
  gw_block_info_t block_info;
  uint8_t rollup_config[GW_MAX_ROLLUP_CONFIG_SIZE];
  uint64_t rollup_config_size;
  /* layer2 syscalls */
  gw_load_fn sys_load;
  gw_get_account_nonce_fn sys_get_account_nonce;
  gw_store_fn sys_store;
  gw_set_program_return_data_fn sys_set_program_return_data;
  gw_create_fn sys_create;
  gw_get_account_id_by_script_hash_fn sys_get_account_id_by_script_hash;
  gw_get_script_hash_by_account_id_fn sys_get_script_hash_by_account_id;
  gw_get_account_script_fn sys_get_account_script;
  gw_load_data_fn sys_load_data;
  gw_store_data_fn sys_store_data;
  gw_get_block_hash_fn sys_get_block_hash;
  gw_get_script_hash_by_prefix_fn sys_get_script_hash_by_prefix;
  gw_recover_account_fn sys_recover_account;
  gw_log_fn sys_log;
  gw_pay_fee_fn sys_pay_fee;
} gw_context_t;

int _ensure_account_exists(gw_context_t *ctx, uint32_t account_id) {
  uint8_t script_hash[32];
  int ret = ctx->sys_get_script_hash_by_account_id(ctx, account_id, script_hash);
  if (ret != 0) {
    return ret;
  }
  for (int i = 0; i < 32; i++) {
    /* if account not exists script_hash will be zero */
    if (script_hash[i] != 0) {
      return 0;
    }
  }
  return GW_ERROR_ACCOUNT_NOT_FOUND;
}

int sys_load(gw_context_t *ctx, uint32_t account_id,
             const uint8_t *key,
             const uint64_t key_len,
             uint8_t value[GW_VALUE_BYTES]) {
  if (ctx == NULL) {
    return GW_ERROR_INVALID_CONTEXT;
  }
  int ret = _ensure_account_exists(ctx, account_id);
  if (ret != 0) {
    return ret;
  }

  if (1 == *(uint32_t*)key) { // SUDT_KEY_FLAG_BALANCE = 1
    // mock balance = 20000
    value[0] = 32;
    value[1] = 78;
    return MOCK_SUCCESS;
  }

  uint8_t raw_key[GW_KEY_BYTES] = {0};
  gw_build_account_key(account_id, key, key_len, raw_key);
  return syscall(GW_SYS_LOAD, raw_key, value, 0, 0, 0, 0);
}

int sys_store(gw_context_t *ctx, uint32_t account_id,
              const uint8_t *key,
              const uint64_t key_len,
              const uint8_t value[GW_VALUE_BYTES]) {
  if (ctx == NULL) {
    return GW_ERROR_INVALID_CONTEXT;
  }
  int ret = _ensure_account_exists(ctx, account_id);
  if (ret != 0) {
    return ret;
  }

  // if (1 == *(uint32_t*)key) { // SUDT_KEY_FLAG_BALANCE = 1
  //   // mock _sudt_set_balance success
  //   return MOCK_SUCCESS;
  // }
  // const uint8_t POLYJUICE_SYSTEM_PREFIX = 0xFF;
  // if (0 == memcmp(&POLYJUICE_SYSTEM_PREFIX, key + 4, sizeof(uint8_t))) {
  //   return MOCK_SUCCESS;
  // }

  uint8_t raw_key[GW_KEY_BYTES];
  gw_build_account_key(account_id, key, key_len, raw_key);

  // mock syscall(GW_SYS_STORE, raw_key, value, 0, 0, 0, 0)
  return gw_update_raw(raw_key, value);
}

int sys_get_account_nonce(gw_context_t *ctx, uint32_t account_id,
                   uint32_t *nonce) {
  if (ctx == NULL) {
    return GW_ERROR_INVALID_CONTEXT;
  }
  int ret = _ensure_account_exists(ctx, account_id);
  if (ret != 0) {
    return ret;
  }

  // uint8_t key[32];
  // gw_build_nonce_key(account_id, key);
  // return syscall(GW_SYS_LOAD, key, value, 0, 0, 0, 0);
  uint8_t key[32] = {0};
  gw_build_account_field_key(account_id, GW_ACCOUNT_NONCE, key);
  uint8_t value[32] = {0};
  ret = syscall(GW_SYS_LOAD, key, value, 0, 0, 0, 0);
  if (ret != 0) {
    return ret;
  }
  memcpy(nonce, value, sizeof(uint32_t));
  return 0;
}

/**
 * set call return data
 * Mock syscall(GW_SYS_SET_RETURN_DATA, data, len, 0, 0, 0, 0)
 */
int sys_set_program_return_data(gw_context_t *ctx,
                                uint8_t *data,
                                uint64_t len) {
  if (ctx == NULL) {
    return GW_ERROR_INVALID_CONTEXT;
  }
  // TODO: print data?
  return MOCK_SUCCESS;
}

/**
 * Get account id by account script_hash
 * Mock syscall(GW_SYS_LOAD_ACCOUNT_ID_BY_SCRIPT_HASH, script_hash, account_id, 0, 0, 0, 0)
 */
int sys_get_account_id_by_script_hash(gw_context_t *ctx,
                                      uint8_t script_hash[32],
                                      uint32_t *account_id) {
  if (ctx == NULL) {
    return GW_ERROR_INVALID_CONTEXT;
  }

  // TODO refactor test_script_hash
  for (size_t i = 0; i < sizeof(test_script_hash) / 32; i++) {
    if (0 == memcmp(script_hash, test_script_hash[i], 32)) {
      *account_id = i;
      return MOCK_SUCCESS;
    }
  }
  return GW_ERROR_NOT_FOUND;
}

/**
 * Get account script_hash by account_id
 * Mock syscall(GW_SYS_LOAD_SCRIPT_HASH_BY_ACCOUNT_ID, account_id, script_hash, 0, 0, 0, 0)
 */
int sys_get_script_hash_by_account_id(gw_context_t *ctx,
                                      uint32_t account_id,
                                      uint8_t script_hash[32]) {
  if (ctx == NULL) {
    return GW_ERROR_INVALID_CONTEXT;
  }

  //TODO: get script_hash from rocketdb
  dbg_print("sys_get_script_hash_by_account_id %d", account_id);
  memcpy(script_hash, test_script_hash[account_id], 32);
  return MOCK_SUCCESS;
}

/**
 * Get account script by account id
 * Mock syscall(GW_SYS_LOAD_ACCOUNT_SCRIPT, script, &inner_len, offset, account_id, 0, 0)
 */
int sys_get_account_script(gw_context_t *ctx, uint32_t account_id,
                           uint64_t *len, uint64_t offset, uint8_t *script) {
  if (ctx == NULL) {
    return GW_ERROR_INVALID_CONTEXT;
  }

  int ret = MOCK_SUCCESS;
  // TODO: load 
  static const uint8_t account1_scripts[] = {117, 0, 0, 0, 16, 0, 0, 0, 48, 0, 0, 0, 49, 0, 0, 0, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 1, 64, 0, 0, 0, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  static const uint8_t account2_scripts[] = {89, 0, 0, 0, 16, 0, 0, 0, 48, 0, 0, 0, 49, 0, 0, 0, 5, 108, 171, 165, 10, 111, 194, 87, 79, 38, 74, 23, 199, 7, 250, 53, 120, 75, 230, 229, 154, 244, 114, 163, 65, 119, 108, 251, 137, 16, 190, 229, 1, 36, 0, 0, 0, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 1, 0, 0, 0};
  static const uint8_t account4_scripts[] = {97, 0, 0, 0, 16, 0, 0, 0, 48, 0, 0, 0, 49, 0, 0, 0, 61, 131, 245, 41, 45, 5, 161, 161, 151, 161, 101, 38, 160, 60, 251, 86, 103, 65, 171, 189, 194, 72, 182, 31, 188, 159, 136, 253, 36, 110, 14, 98, 1, 44, 0, 0, 0, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 2, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0};
  static const uint8_t account5_scripts[] = {109, 0, 0, 0, 16, 0, 0, 0, 48, 0, 0, 0, 49, 0, 0, 0, 5, 108, 171, 165, 10, 111, 194, 87, 79, 38, 74, 23, 199, 7, 250, 53, 120, 75, 230, 229, 154, 244, 114, 163, 65, 119, 108, 251, 137, 16, 190, 229, 1, 56, 0, 0, 0, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 2, 0, 0, 0, 127, 206, 210, 20, 115, 27, 194, 169, 199, 79, 204, 192, 210, 154, 137, 78, 143, 170, 217, 240};
  switch (account_id) {
    case 1:
      *len = sizeof(account1_scripts);
      memcpy(script, account1_scripts + offset, *len - offset);
      break;
    case 2:
      *len = sizeof(account2_scripts);
      memcpy(script, account2_scripts + offset, *len - offset);
      break;
    case 4:
      *len = sizeof(account4_scripts);
      memcpy(script, account4_scripts + offset, *len - offset);
      break;
    case 5:
      *len = sizeof(account5_scripts);
      memcpy(script, account5_scripts + offset, *len - offset);
      break;
    default:
      ret = GW_ERROR_NOT_FOUND;
  }
  return ret;
}

/**
 * Store data by data hash
 */
int sys_store_data(gw_context_t *ctx, uint64_t data_len, uint8_t *data) {
  if (ctx == NULL) {
    return GW_ERROR_INVALID_CONTEXT;
  }

  // mock syscall(GW_SYS_STORE_DATA, data_len, data, 0, 0, 0, 0)
  return gw_store_data(data_len, data);
}

/* Load data by data hash */
int sys_load_data(gw_context_t *ctx, uint8_t data_hash[32], uint64_t *len,
                  uint64_t offset, uint8_t *data) {
  if (ctx == NULL) {
    return GW_ERROR_INVALID_CONTEXT;
  }

  ckb_debug("mock sys_load_data");
  int ret = MOCK_SUCCESS;

  if (0 == memcmp(data_hash, ckb_secp256k1_data_hash, 32)) {
    /* match ckb_secp256k1_data_hash, load secp256k1_data */
    FILE* stream = fopen("./build/secp256k1_data", "rb");
    ret = fread(data, CKB_SECP256K1_DATA_SIZE, 1, stream);
    fclose(stream);
    stream = NULL;
    if (ret != 1) { // ret = The total number of elements successfully read
      return MOCK_SECP256K1_ERROR_LOADING_DATA;
    }
    *len = CKB_SECP256K1_DATA_SIZE;
    return ret;
  }
  
  dbg_print("syscall(GW_SYS_LOAD_DATA, data, &inner_len, offset, data_hash, 0, 0)");
  dbg_print_h256(data_hash);
  // mock syscall(GW_SYS_LOAD_DATA, data, &inner_len, offset, data_hash, 0, 0)
  ret = gw_sys_load_data(data, len, offset, data_hash);
  return ret;
}

/**
 * Load Layer2 Transaction
 * Mock syscall(GW_SYS_LOAD_TRANSACTION, addr, &inner_len, 0, 0, 0, 0)
 */
int _sys_load_l2transaction(uint8_t* addr, uint64_t* len) {
  // load raw tx data from fuzzInput.raw_tx
  gw_load_transaction_from_raw_tx(addr, len);
  return MOCK_SUCCESS;
}

/**
 * Mock syscall(GW_SYS_LOAD_BLOCKINFO, addr, &inner_len, 0, 0, 0, 0)
 * struct BlockInfo {
    block_producer_id: Uint32,
    number: Uint64,
    timestamp: Uint64}
 */
int _sys_load_block_info(void *addr, uint64_t *len) {
  // TODO：
  static uint8_t mock_new_block_info[] = {0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  *len = sizeof(mock_new_block_info);
  memcpy(addr, mock_new_block_info, *len);
  return MOCK_SUCCESS;
}

int sys_get_block_hash(gw_context_t *ctx, uint64_t number,
                       uint8_t block_hash[32]) {
  if (ctx == NULL) {
    return GW_ERROR_INVALID_CONTEXT;
  }

  return syscall(GW_SYS_GET_BLOCK_HASH, block_hash, number, 0, 0, 0, 0);
}

/** 
 * Mock syscall(GW_SYS_GET_SCRIPT_HASH_BY_SHORT_ADDRESS, script_hash, prefix, prefix_len, 0, 0, 0)
 * FIXME: check syscall args A3, A4 in godwoken/crates/generator/src/syscalls/mod.rs
 */ 
int sys_get_script_hash_by_prefix(gw_context_t *ctx, uint8_t *prefix, uint64_t prefix_len,
                                  uint8_t script_hash[32]) {
  if (ctx == NULL) {
    return GW_ERROR_INVALID_CONTEXT;
  }

  if (prefix_len == 0 || prefix_len > 32) {
    return GW_ERROR_INVALID_DATA;
  }

  //TODO: refactor test_script_hash
  for (size_t i = 0; i < sizeof(test_script_hash) / 32; i++) {
    if (0 == memcmp(prefix, test_script_hash[i], 20)) {
      memcpy(script_hash, test_script_hash[i], 32);
      return MOCK_SUCCESS;
    }
  }
  return syscall(GW_SYS_GET_SCRIPT_HASH_BY_SHORT_ADDRESS, script_hash, prefix, prefix_len, 0, 0, 0);
}

/**
 * Mock syscall(GW_SYS_CREATE, script, script_len, account_id, 0, 0, 0)
 */
int sys_create(gw_context_t *ctx, uint8_t *script, uint64_t script_len,
               uint32_t *account_id) {
  if (ctx == NULL) {
    return GW_ERROR_INVALID_CONTEXT;
  }

  //TODO: Mock SYS_CREATE syscall
  *account_id = 4;
  return MOCK_SUCCESS;
}

int sys_recover_account(struct gw_context_t *ctx,
                        uint8_t message[32],
                        uint8_t *signature,
                        uint64_t signature_len,
                        uint8_t code_hash[32],
                        uint8_t *script,
                        uint64_t *script_len) {
  if (ctx == NULL) {
    return GW_ERROR_INVALID_CONTEXT;
  }

  volatile uint64_t inner_script_len = 0;
  int ret = syscall(GW_SYS_RECOVER_ACCOUNT, script, &inner_script_len,
                    message, signature, signature_len, code_hash);
  *script_len = inner_script_len;
  return ret;
}
/**
 * Mock syscall(GW_SYS_LOG, account_id, service_flag, data_length, data, 0, 0)
 */
int sys_log(gw_context_t *ctx, uint32_t account_id, uint8_t service_flag,
            uint64_t data_length, const uint8_t *data) {
  if (ctx == NULL) {
    return GW_ERROR_INVALID_CONTEXT;
  }
  int ret = _ensure_account_exists(ctx, account_id);
  if (ret != 0) {
    return ret;
  }

  dbg_print("GW_LOG_FLAG_%d...", service_flag);
  return MOCK_SUCCESS;
}

int sys_pay_fee(gw_context_t *ctx, const uint8_t *payer_addr,
                const uint64_t short_addr_len, uint32_t sudt_id, uint128_t amount) {
  if (ctx == NULL) {
    return GW_ERROR_INVALID_CONTEXT;
  }
  int ret = _ensure_account_exists(ctx, sudt_id);
  if (ret != 0) {
    return ret;
  }

  return syscall(GW_SYS_PAY_FEE, payer_addr, short_addr_len, sudt_id, &amount, 0, 0);
}

/**
 * Mock syscall(GW_SYS_PAY_FEE, payer_addr, short_addr_len, sudt_id, &amount, 0, 0)
 */
int sys_pay_fee(gw_context_t *ctx, const uint8_t *payer_addr,
                const uint64_t short_addr_len, uint32_t sudt_id, uint128_t amount) {
  if (ctx == NULL) {
    return GW_ERROR_INVALID_CONTEXT;
  }
  int ret = _ensure_account_exists(ctx, sudt_id);
  if (ret != 0) {
    return ret;
  }

  // payer: payer_addr[short_addr_len]
  dbg_print("[mock contract syscall: SYS_PAY_FEE] sudt_id: %d, amount: %ld",
            sudt_id, amount);
  return MOCK_SUCCESS;
}

/**
 * Mock syscall(GW_SYS_LOAD_ROLLUP_CONFIG, addr, &inner_len, 0, 0, 0, 0)
 * and verify the RollupConfig
 */
int _sys_load_rollup_config(uint8_t *addr, uint64_t *len) {
  // FIXME: load rollup_config from godwoken lib
  static const uint8_t rollup_config[] = {189, 1, 0, 0, 60, 0, 0, 0, 92, 0, 0, 0, 124, 0, 0, 0, 156, 0, 0, 0, 188, 0, 0, 0, 220, 0, 0, 0, 252, 0, 0, 0, 28, 1, 0, 0, 60, 1, 0, 0, 68, 1, 0, 0, 76, 1, 0, 0, 84, 1, 0, 0, 85, 1, 0, 0, 89, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 5, 108, 171, 165, 10, 111, 194, 87, 79, 38, 74, 23, 199, 7, 250, 53, 120, 75, 230, 229, 154, 244, 114, 163, 65, 119, 108, 251, 137, 16, 190, 229};
  *len = sizeof(rollup_config);
  memcpy(addr, rollup_config, *len);

  if (*len > GW_MAX_ROLLUP_CONFIG_SIZE) {
    ckb_debug("length too long");
    return GW_ERROR_INVALID_DATA;
  }
  mol_seg_t config_seg;
  config_seg.ptr = addr;
  config_seg.size = *len;
  if (MolReader_RollupConfig_verify(&config_seg, false) != MOL_OK) {
    ckb_debug("rollup config cell data is not RollupConfig format");
    return GW_ERROR_INVALID_DATA;
  }
  return MOCK_SUCCESS;
}

int gw_context_init(gw_context_t *ctx) {
  /* setup syscalls */
  ctx->sys_load = sys_load;
  ctx->sys_store = sys_store;
  ctx->sys_set_program_return_data = sys_set_program_return_data;
  ctx->sys_create = sys_create;
  ctx->sys_get_account_id_by_script_hash = sys_get_account_id_by_script_hash;
  ctx->sys_get_script_hash_by_account_id = sys_get_script_hash_by_account_id;
  ctx->sys_get_account_nonce = sys_get_account_nonce;
  ctx->sys_get_account_script = sys_get_account_script;
  ctx->sys_store_data = sys_store_data;
  ctx->sys_load_data = sys_load_data;
  ctx->sys_get_block_hash = sys_get_block_hash;
  ctx->sys_get_script_hash_by_prefix = sys_get_script_hash_by_prefix;
  ctx->sys_recover_account = sys_recover_account;
  ctx->sys_pay_fee = sys_pay_fee;
  ctx->sys_log = sys_log;

  /* initialize context */
  uint8_t tx_buf[GW_MAX_L2TX_SIZE] = {0};
  uint64_t len = GW_MAX_L2TX_SIZE;
  int ret = _sys_load_l2transaction(tx_buf, &len);
  if (ret != 0) {
    return ret;
  }
  dbg_print("[gw_context_init] l2tx size: %d", len);
  if (len > GW_MAX_L2TX_SIZE) {
    return GW_ERROR_INVALID_DATA;
  }

  mol_seg_t l2transaction_seg;
  l2transaction_seg.ptr = tx_buf;
  l2transaction_seg.size = len;
  ret = gw_parse_transaction_context(&ctx->transaction_context,
                                     &l2transaction_seg);
  dbg_print("[gw_context_init] ret of gw_parse_transaction_context: %d", ret);
  if (ret != 0) {
    return ret;
  }

  uint8_t block_info_buf[sizeof(MolDefault_BlockInfo)] = {0};
  len = sizeof(block_info_buf);
  ret = _sys_load_block_info(block_info_buf, &len);
  dbg_print("[gw_context_init] ret of _sys_load_block_info: %d", ret);
  if (ret != 0) {
    return ret;
  }

  mol_seg_t block_info_seg;
  block_info_seg.ptr = block_info_buf;
  block_info_seg.size = len;
  ret = gw_parse_block_info(&ctx->block_info, &block_info_seg);
  dbg_print("[gw_context_init] ret of gw_parse_block_info: %d", ret);
  if (ret != 0) {
    return ret;
  }

  ctx->rollup_config_size = GW_MAX_ROLLUP_CONFIG_SIZE;
  ret = _sys_load_rollup_config(ctx->rollup_config, &ctx->rollup_config_size);
  dbg_print("[gw_context_init] ret of _sys_load_rollup_config: %d", ret);
  if (ret != 0) {
    return ret;
  }

  return 0;
}

int gw_finalize(gw_context_t *ctx) {
  /* do nothing */
  return 0;
}

int gw_verify_sudt_account(gw_context_t *ctx, uint32_t sudt_id) {
  uint8_t script_buffer[GW_MAX_SCRIPT_SIZE];
  uint64_t script_len = GW_MAX_SCRIPT_SIZE;
  int ret = sys_get_account_script(ctx, sudt_id, &script_len, 0, script_buffer);
  if (ret != 0) {
    return ret;
  }
  if (script_len > GW_MAX_SCRIPT_SIZE) {
    return GW_ERROR_INVALID_SUDT_SCRIPT;
  }
  mol_seg_t script_seg;
  script_seg.ptr = script_buffer;
  script_seg.size = script_len;
  if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
    ckb_debug("load account script: invalid script");
    return GW_ERROR_INVALID_SUDT_SCRIPT;
  }
  mol_seg_t code_hash_seg = MolReader_Script_get_code_hash(&script_seg);
  mol_seg_t hash_type_seg = MolReader_Script_get_hash_type(&script_seg);

  mol_seg_t rollup_config_seg;
  rollup_config_seg.ptr = ctx->rollup_config;
  rollup_config_seg.size = ctx->rollup_config_size;
  mol_seg_t l2_sudt_validator_script_type_hash =
    MolReader_RollupConfig_get_l2_sudt_validator_script_type_hash(&rollup_config_seg);
  if (memcmp(l2_sudt_validator_script_type_hash.ptr, code_hash_seg.ptr, 32) != 0) {
    return GW_ERROR_INVALID_SUDT_SCRIPT;
  }
  if (*hash_type_seg.ptr != 1) {
    return GW_ERROR_INVALID_SUDT_SCRIPT;
  }
  return 0;
}
#endif
