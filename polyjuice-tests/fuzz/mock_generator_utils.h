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

/* syscalls */
#define GW_SYS_STORE 3051
#define GW_SYS_LOAD 3052
#define GW_SYS_SET_RETURN_DATA 3061
#define GW_SYS_CREATE 3071
/* internal syscall only for generator */
#define GW_SYS_LOAD_TRANSACTION 4051
#define GW_SYS_LOAD_BLOCKINFO 4052
#define GW_SYS_LOAD_SCRIPT_HASH_BY_ACCOUNT_ID 4053
#define GW_SYS_LOAD_ACCOUNT_ID_BY_SCRIPT_HASH 4054
#define GW_SYS_LOAD_ACCOUNT_SCRIPT 4055
#define GW_SYS_STORE_DATA 4056
#define GW_SYS_LOAD_DATA 4057
#define GW_SYS_GET_BLOCK_HASH 4058
#define GW_SYS_GET_SCRIPT_HASH_BY_PREFIX 4059
#define GW_SYS_RECOVER_ACCOUNT 4060
#define GW_SYS_LOG 4061
#define GW_SYS_LOAD_ROLLUP_CONFIG 4062

/* Godwoken Service Flag */
// #define GW_LOG_SUDT_TRANSFER    0
// #define GW_LOG_SUDT_PAY_FEE     1
// #define GW_LOG_POLYJUICE_SYSTEM 2
// #define GW_LOG_POLYJUICE_USER   3

#define ERROR_NOT_FOUND 203
#define MOCK_SUCCESS 0
#define MOCK_SECP256K1_ERROR_LOADING_DATA -101

static const uint8_t test_script_hash[5][32] = { // FIXME
  {231, 196, 69, 164, 212, 229, 83, 6, 137, 240, 237, 105, 234, 223, 101, 133, 197, 66, 85, 214, 112, 85, 87, 71, 17, 170, 138, 126, 128, 173, 186, 76},
  {50, 15, 9, 23, 166, 82, 42, 69, 226, 148, 203, 184, 168, 8, 210, 62, 226, 187, 187, 21, 122, 141, 152, 55, 88, 230, 63, 204, 23, 3, 166, 102},
  {221, 60, 233, 16, 227, 19, 49, 118, 137, 43, 193, 160, 145, 21, 141, 6, 43, 206, 191, 210, 105, 160, 112, 23, 155, 184, 101, 113, 47, 247, 216, 122},
  {48, 160, 141, 250, 92, 214, 34, 124, 231, 78, 106, 179, 173, 80, 61, 55, 161, 156, 45, 114, 214, 222, 9, 77, 4, 104, 52, 44, 30, 149, 27, 36},
  {103, 167, 175, 25, 71, 242, 5, 31, 102, 236, 38, 188, 223, 212, 241, 99, 13, 4, 40, 150, 151, 55, 40, 147, 64, 29, 108, 50, 37, 159, 55, 137}};


typedef struct gw_context_t {
  /* verification context */
  gw_transaction_context_t transaction_context;
  gw_block_info_t block_info;
  uint8_t rollup_config[GW_MAX_ROLLUP_CONFIG_SIZE];
  uint64_t rollup_config_size;
  /* layer2 syscalls */
  gw_load_fn sys_load;
  gw_load_nonce_fn sys_load_nonce;
  gw_store_fn sys_store;
  gw_set_program_return_data_fn sys_set_program_return_data;
  gw_create_fn sys_create;
  gw_get_account_id_by_script_hash_fn sys_get_account_id_by_script_hash;
  gw_get_script_hash_by_account_id_fn sys_get_script_hash_by_account_id;
  gw_get_account_nonce_fn sys_get_account_nonce;
  gw_get_account_script_fn sys_get_account_script;
  gw_load_data_fn sys_load_data;
  gw_store_data_fn sys_store_data;
  gw_get_block_hash_fn sys_get_block_hash;
  gw_get_script_hash_by_prefix_fn sys_get_script_hash_by_prefix;
  gw_recover_account_fn sys_recover_account;
  gw_log_fn sys_log;
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

  if (1 == *(uint32_t*)key) { // SUDT_KEY_FLAG_BALANCE = 1
    // mock _sudt_set_balance success
    return MOCK_SUCCESS;
  }
  const uint8_t POLYJUICE_SYSTEM_PREFIX = 0xFF;
  if (0 == memcmp(&POLYJUICE_SYSTEM_PREFIX, key + 4, sizeof(uint8_t))) {
    //FIXME mock store_contract_code
    return MOCK_SUCCESS;
  }

  uint8_t raw_key[GW_KEY_BYTES];
  gw_build_account_key(account_id, key, key_len, raw_key);
  return syscall(GW_SYS_STORE, raw_key, value, 0, 0, 0, 0);
}

int sys_load_nonce(gw_context_t *ctx, uint32_t account_id,
                   uint8_t value[GW_VALUE_BYTES]) {
  if (ctx == NULL) {
    return GW_ERROR_INVALID_CONTEXT;
  }
  int ret = _ensure_account_exists(ctx, account_id);
  if (ret != 0) {
    return ret;
  }

  uint8_t key[32] = {0};
  dbg_print("sys_get_account_nonce => account_id = %d => key:", account_id);
  gw_build_account_field_key(account_id, GW_ACCOUNT_NONCE, key);
  uint8_t value[32] = {0};
  ret = syscall(GW_SYS_LOAD, key, value, 0, 0, 0, 0);
  if (ret != 0) {
    return ret;
  }
  memcpy(nonce, value, sizeof(uint32_t));
  return MOCK_SUCCESS;
}

/**
 * set call return data
 * Mock syscall(GW_SYS_SET_RETURN_DATA, data, len, 0, 0, 0, 0)
 */
int sys_set_program_return_data(gw_context_t *ctx,
                                uint8_t *data,
                                uint64_t len) {
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
 // TODO refactor test_script_hash
 for (size_t i = 0; i < sizeof(test_script_hash) / 32; i++) {
   if (0 == memcmp(script_hash, test_script_hash[i], 32)) {
     *account_id = i;
     return MOCK_SUCCESS;
   }
 }
 return ERROR_NOT_FOUND;
}

/**
 * Get account script_hash by account_id
 * Mock syscall(GW_SYS_LOAD_SCRIPT_HASH_BY_ACCOUNT_ID, account_id, script_hash, 0, 0, 0, 0)
 */
int sys_get_script_hash_by_account_id(gw_context_t *ctx,
                                      uint32_t account_id,
                                      uint8_t script_hash[32]) {
  //TODO: get script_hash from rocketdb
  memcpy(script_hash, test_script_hash[account_id], 32);
  return MOCK_SUCCESS;
}

/**
 * Get account script by account id
 * Mock syscall(GW_SYS_LOAD_ACCOUNT_SCRIPT, script, &inner_len, offset, account_id, 0, 0)
 */
int sys_get_account_script(gw_context_t *ctx, uint32_t account_id,
                           uint64_t *len, uint64_t offset, uint8_t *script) {
  int ret = MOCK_SUCCESS;
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
      ret = ERROR_NOT_FOUND;
  }
  return ret;
}

/**
 * Store data by data hash
 * Mock syscall(GW_SYS_STORE_DATA, data_len, data, 0, 0, 0, 0)
 */
int sys_store_data(gw_context_t *ctx, uint64_t data_len, uint8_t *data) {
  //TODO: data hash = new_blake2b().update(data)
  return MOCK_SUCCESS;
}

/* Load data by data hash */
int sys_load_data(gw_context_t *ctx, uint8_t data_hash[32], uint64_t *len,
                  uint64_t offset, uint8_t *data) {
  ckb_debug("mock sys_load_data->GW_SYS_LOAD_DATA");
  int ret = 0;

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
    return MOCK_SUCCESS;
  }
  
  volatile uint64_t inner_len = *len;
  ret = syscall(GW_SYS_LOAD_DATA, data, &inner_len, offset, data_hash, 0, 0);
  *len = inner_len;
  return ret;
}

/**
 * Load Layer2 Transaction
 * Mock syscall(GW_SYS_LOAD_TRANSACTION, addr, &inner_len, 0, 0, 0, 0)
 */
int _sys_load_l2transaction(void *addr, uint64_t *len) {
  // TODO：raw tx data from fuzzInput

  static uint8_t get_chain_id_tx[] = {92, 0, 0, 0, 20, 0, 0, 0, 24, 0, 0, 0, 28, 0, 0, 0, 32, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 56, 0, 0, 0, 255, 255, 255, 80, 79, 76, 89, 0, 8, 82, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 109, 76, 230, 60};
  // version@20210625: {92, 0, 0, 0, 20, 0, 0, 0, 24, 0, 0, 0, 28, 0, 0, 0, 32, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 56, 0, 0, 0, 255, 255, 255, 80, 79, 76, 89, 0, 8, 82, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 109, 76, 230, 60};
  *len = sizeof(get_chain_id_tx);
  dbg_print("length of get_chain_id_tx: %ld", *len);
  memcpy(addr, get_chain_id_tx, *len);
  return MOCK_SUCCESS;

  // create account and deploy getChainId contract
  static uint8_t deploy_get_chain_id_contract[] = {73, 1, 0, 0, 20, 0, 0, 0, 24, 0, 0, 0, 28, 0, 0, 0, 32, 0, 0, 0, 4, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 37, 1, 0, 0, 255, 255, 255, 80, 79, 76, 89, 3, 240, 85, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 241, 0, 0, 0, 96, 128, 96, 64, 82, 52, 128, 21, 97, 0, 17, 87, 96, 0, 96, 0, 253, 91, 80, 97, 0, 23, 86, 91, 96, 204, 128, 97, 0, 37, 96, 0, 57, 96, 0, 243, 254, 96, 128, 96, 64, 82, 52, 128, 21, 96, 16, 87, 96, 0, 96, 0, 253, 91, 80, 96, 4, 54, 16, 96, 44, 87, 96, 0, 53, 96, 224, 28, 128, 99, 109, 76, 230, 60, 20, 96, 50, 87, 96, 44, 86, 91, 96, 0, 96, 0, 253, 91, 96, 56, 96, 76, 86, 91, 96, 64, 81, 96, 67, 145, 144, 96, 112, 86, 91, 96, 64, 81, 128, 145, 3, 144, 243, 91, 96, 0, 96, 0, 70, 144, 80, 128, 145, 80, 80, 96, 92, 86, 80, 91, 144, 86, 96, 149, 86, 91, 96, 105, 129, 96, 138, 86, 91, 130, 82, 91, 80, 80, 86, 91, 96, 0, 96, 32, 130, 1, 144, 80, 96, 131, 96, 0, 131, 1, 132, 96, 98, 86, 91, 91, 146, 145, 80, 80, 86, 91, 96, 0, 129, 144, 80, 91, 145, 144, 80, 86, 91, 254, 162, 100, 105, 112, 102, 115, 88, 34, 18, 32, 3, 36, 140, 112, 116, 35, 57, 185, 199, 86, 232, 210, 111, 220, 122, 33, 250, 178, 163, 13, 127, 44, 169, 160, 247, 149, 71, 178, 184, 168, 61, 64, 100, 115, 111, 108, 99, 67, 0, 8, 2, 0, 51};
  // version@20210625: {73, 1, 0, 0, 20, 0, 0, 0, 24, 0, 0, 0, 28, 0, 0, 0, 32, 0, 0, 0, 3, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 37, 1, 0, 0, 255, 255, 255, 80, 79, 76, 89, 3, 240, 85, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 241, 0, 0, 0, 96, 128, 96, 64, 82, 52, 128, 21, 97, 0, 17, 87, 96, 0, 96, 0, 253, 91, 80, 97, 0, 23, 86, 91, 96, 204, 128, 97, 0, 37, 96, 0, 57, 96, 0, 243, 254, 96, 128, 96, 64, 82, 52, 128, 21, 96, 16, 87, 96, 0, 96, 0, 253, 91, 80, 96, 4, 54, 16, 96, 44, 87, 96, 0, 53, 96, 224, 28, 128, 99, 109, 76, 230, 60, 20, 96, 50, 87, 96, 44, 86, 91, 96, 0, 96, 0, 253, 91, 96, 56, 96, 76, 86, 91, 96, 64, 81, 96, 67, 145, 144, 96, 112, 86, 91, 96, 64, 81, 128, 145, 3, 144, 243, 91, 96, 0, 96, 0, 70, 144, 80, 128, 145, 80, 80, 96, 92, 86, 80, 91, 144, 86, 96, 149, 86, 91, 96, 105, 129, 96, 138, 86, 91, 130, 82, 91, 80, 80, 86, 91, 96, 0, 96, 32, 130, 1, 144, 80, 96, 131, 96, 0, 131, 1, 132, 96, 98, 86, 91, 91, 146, 145, 80, 80, 86, 91, 96, 0, 129, 144, 80, 91, 145, 144, 80, 86, 91, 254, 162, 100, 105, 112, 102, 115, 88, 34, 18, 32, 3, 36, 140, 112, 116, 35, 57, 185, 199, 86, 232, 210, 111, 220, 122, 33, 250, 178, 163, 13, 127, 44, 169, 160, 247, 149, 71, 178, 184, 168, 61, 64, 100, 115, 111, 108, 99, 67, 0, 8, 2, 0, 51};
  *len = sizeof(deploy_get_chain_id_contract);
  dbg_print("length of deploy_get_chain_id_contract: %ld", *len);
  memcpy(addr, deploy_get_chain_id_contract, *len);
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
  return syscall(GW_SYS_GET_BLOCK_HASH, block_hash, number, 0, 0, 0, 0);
}

/** 
 * Mock syscall(GW_SYS_GET_SCRIPT_HASH_BY_PREFIX, script_hash, prefix, prefix_len, 0, 0, 0)
 * FIXME: check syscall args A3, A4 in godwoken/crates/generator/src/syscalls/mod.rs
 */ 
int sys_get_script_hash_by_prefix(gw_context_t *ctx, uint8_t *prefix, uint64_t prefix_len,
                                  uint8_t script_hash[32]) {
  //TODO: refactor test_script_hash
  for (size_t i = 0; i < sizeof(test_script_hash) / 32; i++) {
    if (0 == memcmp(prefix, test_script_hash[i], 20)) {
      memcpy(script_hash, test_script_hash[i], 32);
      return MOCK_SUCCESS;
    }
  }
  return ERROR_NOT_FOUND;
}

/**
 * Mock syscall(GW_SYS_CREATE, script, script_len, account_id, 0, 0, 0)
 */
int sys_create(gw_context_t *ctx, uint8_t *script, uint64_t script_len,
               uint32_t *account_id) {
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
  ctx->sys_load_nonce = sys_load_nonce;
  ctx->sys_store = sys_store;
  ctx->sys_set_program_return_data = sys_set_program_return_data;
  ctx->sys_create = sys_create;
  ctx->sys_get_account_id_by_script_hash = sys_get_account_id_by_script_hash;
  ctx->sys_get_script_hash_by_account_id = sys_get_script_hash_by_account_id;
  ctx->sys_get_account_script = sys_get_account_script;
  ctx->sys_store_data = sys_store_data;
  ctx->sys_load_data = sys_load_data;
  ctx->sys_get_block_hash = sys_get_block_hash;
  ctx->sys_get_script_hash_by_prefix = sys_get_script_hash_by_prefix;
  ctx->sys_recover_account = sys_recover_account;
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
