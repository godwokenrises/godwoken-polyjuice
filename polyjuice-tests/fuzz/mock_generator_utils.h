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
// #include "polyjuice_utils.h"

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

#define MOCK_SUCCESS 0
#define MOCK_SECP256K1_ERROR_LOADING_DATA -101

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

  uint8_t key[32];
  gw_build_nonce_key(account_id, key);
  return syscall(GW_SYS_LOAD, key, value, 0, 0, 0, 0);
}

/* set call return data */
int sys_set_program_return_data(gw_context_t *ctx,
                                uint8_t *data,
                                uint64_t len) {
  return syscall(GW_SYS_SET_RETURN_DATA, data, len, 0, 0, 0, 0);
}

/* Get account id by account script_hash */
int sys_get_account_id_by_script_hash(gw_context_t *ctx,
                                      uint8_t script_hash[32],
                                      uint32_t *account_id) {
  return syscall(GW_SYS_LOAD_ACCOUNT_ID_BY_SCRIPT_HASH, script_hash, account_id,
                 0, 0, 0, 0);
}

/* Get account script_hash by account id */
int sys_get_script_hash_by_account_id(gw_context_t *ctx,
                                      uint32_t account_id,
                                      uint8_t script_hash[32]) {
  return syscall(GW_SYS_LOAD_SCRIPT_HASH_BY_ACCOUNT_ID, account_id, script_hash,
                 0, 0, 0, 0);
}

/* Get account script by account id */
int sys_get_account_script(gw_context_t *ctx, uint32_t account_id,
                           uint64_t *len, uint64_t offset, uint8_t *script) {
  volatile uint64_t inner_len = *len;
  int ret = syscall(GW_SYS_LOAD_ACCOUNT_SCRIPT, script, &inner_len, offset, account_id, 0, 0);
  *len = inner_len;
  return ret;
}
/* Store data by data hash */
int sys_store_data(gw_context_t *ctx, uint64_t data_len, uint8_t *data) {
  return syscall(GW_SYS_STORE_DATA, data_len, data, 0, 0, 0, 0);
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

int _sys_load_l2transaction(void *addr, uint64_t *len) {
  volatile uint64_t inner_len = *len;
  int ret = syscall(GW_SYS_LOAD_TRANSACTION, addr, &inner_len, 0, 0, 0, 0);
  *len = inner_len;
  return ret;
}

int _sys_load_block_info(void *addr, uint64_t *len) {
  volatile uint64_t inner_len = *len;
  int ret = syscall(GW_SYS_LOAD_BLOCKINFO, addr, &inner_len, 0, 0, 0, 0);
  *len = inner_len;
  return ret;
}

int sys_get_block_hash(gw_context_t *ctx, uint64_t number,
                       uint8_t block_hash[32]) {
  return syscall(GW_SYS_GET_BLOCK_HASH, block_hash, number, 0, 0, 0, 0);
}

int sys_get_script_hash_by_prefix(gw_context_t *ctx, uint8_t *prefix, uint64_t prefix_len,
                                  uint8_t script_hash[32]) {
  return syscall(GW_SYS_GET_SCRIPT_HASH_BY_PREFIX, script_hash, prefix, prefix_len, 0, 0, 0);
}

int sys_create(gw_context_t *ctx, uint8_t *script, uint64_t script_len,
               uint32_t *account_id) {
  return syscall(GW_SYS_CREATE, script, script_len, account_id, 0, 0, 0);
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

int sys_log(gw_context_t *ctx, uint32_t account_id, uint8_t service_flag,
            uint64_t data_length, const uint8_t *data) {
  if (ctx == NULL) {
    return GW_ERROR_INVALID_CONTEXT;
  }
  int ret = _ensure_account_exists(ctx, account_id);
  if (ret != 0) {
    return ret;
  }

  return syscall(GW_SYS_LOG, account_id, service_flag, data_length, data, 0, 0);
}

int _sys_load_rollup_config(uint8_t *addr, uint64_t *len) {
  volatile uint64_t inner_len = *len;
  int ret = syscall(GW_SYS_LOAD_ROLLUP_CONFIG, addr, &inner_len, 0, 0, 0, 0);
  *len = inner_len;

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

  return ret;
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
  printf("ret of _sys_load_l2transaction: %d\n", ret);
  if (ret != 0) {
    return ret;
  }
  if (len > GW_MAX_L2TX_SIZE) {
    return GW_ERROR_INVALID_DATA;
  }

  mol_seg_t l2transaction_seg;
  l2transaction_seg.ptr = tx_buf;
  l2transaction_seg.size = len;
  ret = gw_parse_transaction_context(&ctx->transaction_context,
                                     &l2transaction_seg);
  if (ret != 0) {
    return ret;
  }

  uint8_t block_info_buf[sizeof(MolDefault_BlockInfo)] = {0};
  len = sizeof(block_info_buf);
  ret = _sys_load_block_info(block_info_buf, &len);
  if (ret != 0) {
    return ret;
  }

  mol_seg_t block_info_seg;
  block_info_seg.ptr = block_info_buf;
  block_info_seg.size = len;
  ret = gw_parse_block_info(&ctx->block_info, &block_info_seg);
  if (ret != 0) {
    return ret;
  }

  ctx->rollup_config_size = GW_MAX_ROLLUP_CONFIG_SIZE;
  ret = _sys_load_rollup_config(ctx->rollup_config, &ctx->rollup_config_size);
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
