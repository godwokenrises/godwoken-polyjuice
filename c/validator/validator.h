#ifndef GW_VALIDATOR_H_
#define GW_VALIDATOR_H_

#include "ckb_syscalls.h"
#include "common.h"

#define MAX_BUF_SIZE 65536


typedef struct {
  uint8_t key[32];
  uint8_t value[32];
} gw_kv_pair_t;

typedef struct {
  gw_context_t gw_ctx;
  gw_state_t *kv_state;
  /* SMT proof */
  uint8_t *kv_state_proof;
  /* To proof the block is in the chain */
  uint8_t *block_proof;
  /* To proof the transaction is in the chain */
  uint8_t *tx_proof;
} gw_validator_context_t;

int sys_load(void *ctx, uint32_t account_id, const uint8_t key[GW_KEY_BYTES],
             uint8_t value[GW_VALUE_BYTES]) {
  gw_context_t *gw_ctx = (gw_context_t *)ctx;
  if (gw_ctx == NULL) {
    return GW_ERROR_INVALID_CONTEXT;
  }
  uint8_t raw_key[GW_KEY_BYTES] = {0};
  gw_build_account_key(account_id, key, raw_key);
  /* FIXME */
  return -1;
}
int sys_store(void *ctx, uint32_t account_id, const uint8_t key[GW_KEY_BYTES],
              const uint8_t value[GW_VALUE_BYTES]) {
  gw_context_t *gw_ctx = (gw_context_t *)ctx;
  if (gw_ctx == NULL) {
    return GW_ERROR_INVALID_CONTEXT;
  }
  uint8_t raw_key[GW_KEY_BYTES];
  gw_build_account_key(account_id, key, raw_key);
  /* FIXME */
  return -1;
}

int sys_load_nonce(void *ctx, uint32_t account_id, uint8_t value[GW_VALUE_BYTES]) {
  uint8_t key[32];
  gw_build_nonce_key(account_id, key);
  /* FIXME */
  return -1;
}

/* set call return data */
int sys_set_program_return_data(void *ctx, uint8_t *data, uint32_t len) {
  /* FIXME */
  return -1;
}

/* Get account id by account script_hash */
int sys_get_account_id_by_script_hash(void *ctx, uint8_t script_hash[32],
                                      uint32_t *account_id) {
  /* FIXME */
  return -1;
}

/* Get account script_hash by account id */
int sys_get_script_hash_by_account_id(void *ctx, uint32_t account_id,
                                      uint8_t script_hash[32]) {
  /* FIXME */
  return -1;
}

/* Get account script by account id */
int sys_get_account_script(void *ctx, uint32_t account_id, uint32_t *len,
                         uint32_t offset, uint8_t *script) {
  /* FIXME */
  return -1;
}
/* Store data by data hash */
int sys_store_data(void *ctx,
                 uint32_t data_len,
                 uint8_t *data) {
  /* FIXME */
  return -1;
}
/* Load data by data hash */
int sys_load_data(void *ctx, uint8_t data_hash[32],
                 uint32_t *len, uint32_t offset, uint8_t *data) {
  /* FIXME */
  return -1;
}

int _sys_load_l2transaction(void *addr, uint64_t *len) {
  /* FIXME */
  return -1;
}

int _sys_load_block_info(void *addr, uint64_t *len) {
  /* FIXME */
  return -1;
}

int sys_create(void *ctx, uint8_t *script, uint32_t script_len,
               uint32_t *account_id) {
  /* FIXME */
  return -1;
}

int sys_log(void *ctx, uint32_t account_id, uint32_t data_length,
            const uint8_t *data) {
  /* FIXME */
  return -1;
}

int gw_context_init(gw_validator_context_t *context) {
  gw_context_t *gw_ctx = &context->gw_ctx;
  memset(gw_ctx, 0, sizeof(gw_context_t));
  /* setup syscalls */
  gw_ctx->sys_load = sys_load;
  gw_ctx->sys_load_nonce = sys_load_nonce;
  gw_ctx->sys_store = sys_store;
  gw_ctx->sys_set_program_return_data = sys_set_program_return_data;
  gw_ctx->sys_create = sys_create;
  gw_ctx->sys_get_account_id_by_script_hash =
      sys_get_account_id_by_script_hash;
  gw_ctx->sys_get_script_hash_by_account_id =
      sys_get_script_hash_by_account_id;
  gw_ctx->sys_get_account_script = sys_get_account_script;
  gw_ctx->sys_store_data = sys_store_data;
  gw_ctx->sys_load_data = sys_load_data;
  gw_ctx->sys_log = sys_log;

  /* initialize context */
  uint8_t buf[MAX_BUF_SIZE] = {0};
  uint64_t len = MAX_BUF_SIZE;
  int ret = _sys_load_l2transaction(buf, &len);
  if (ret != 0) {
    return ret;
  }
  if (len > MAX_BUF_SIZE) {
    return GW_ERROR_INVALID_DATA;
  }

  mol_seg_t l2transaction_seg;
  l2transaction_seg.ptr = buf;
  l2transaction_seg.size = len;
  ret = gw_parse_transaction_context(&gw_ctx->transaction_context,
                                     &l2transaction_seg);
  if (ret != 0) {
    return ret;
  }

  len = MAX_BUF_SIZE;
  ret = _sys_load_block_info(buf, &len);
  if (ret != 0) {
    return ret;
  }
  if (len > MAX_BUF_SIZE) {
    return GW_ERROR_INVALID_DATA;
  }

  mol_seg_t block_info_seg;
  block_info_seg.ptr = buf;
  block_info_seg.size = len;
  ret = gw_parse_block_info(&gw_ctx->block_info, &block_info_seg);
  if (ret != 0) {
    return ret;
  }

  return 0;
}

#endif
