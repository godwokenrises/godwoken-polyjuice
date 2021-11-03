
#ifndef OTHER_CONTRACTS_H_
#define OTHER_CONTRACTS_H_

#include "polyjuice_utils.h"

/* Gas fee */
#define RECOVER_ACCOUNT_GAS 3600 /* more than ecrecover */
#define ETH_TO_GODWOKEN_ADDR_GAS 300

int recover_account_gas(const uint8_t* input_src,
                        const size_t input_size,
                        uint64_t* gas) {
  *gas = RECOVER_ACCOUNT_GAS;
  return 0;
}

/* Recover an EoA account script hash by signature

  input: (the input data is from abi.encode(mesage, signature, code_hash))
  ======
    input[ 0..32]  => message
    input[32..64]  => offset of signature part
    input[64..96]  => code_hash (EoA lock hash)
    input[96..128] => length of signature data
    input[128..]   => signature data

  output (32 bytes):
  =======
    output[0..32] => account script hash
 */
int recover_account(gw_context_t* ctx,
                    const uint8_t* code_data,
                    const size_t code_size,
                    bool is_static_call,
                    const uint8_t* input_src,
                    const size_t input_size,
                    uint8_t** output, size_t* output_size) {
  if (input_size < 128) {
    debug_print_int("input size too small", input_size);
    return ERROR_RECOVER_ACCOUNT;
  }
  int ret;
  uint8_t *message = (uint8_t *)input_src;
  uint8_t *code_hash = (uint8_t *)input_src + 64;
  uint8_t *signature = (uint8_t *)input_src + 128;
  uint64_t signature_len = 0;
  ret = parse_u64(input_src + 96, &signature_len);
  if (ret != 0) {
    debug_print_int("parse signature length failed", ret);
    return ERROR_RECOVER_ACCOUNT;
  }
  if (signature_len + 128 > input_size) {
    debug_print_int("invalid input_size", input_size);
    return ERROR_RECOVER_ACCOUNT;
  }
  uint8_t script[GW_MAX_SCRIPT_SIZE];
  uint64_t script_len = GW_MAX_SCRIPT_SIZE;
  ret = ctx->sys_recover_account(ctx, message, signature, signature_len, code_hash, script, &script_len);
  if (ret != 0) {
    debug_print_int("call sys_recover_account failed", ret);
    /* wrong code_hash is fatal, so we return the error code here */
    if (is_fatal_error(ret)) {
      return FATAL_PRECOMPILED_CONTRACTS;
    } else {
      return ERROR_RECOVER_ACCOUNT;
    }
  }
  *output = (uint8_t *)malloc(32);
  if (*output == NULL) {
    ckb_debug("malloc failed");
    return FATAL_PRECOMPILED_CONTRACTS;
  }
  *output_size = 32;
  blake2b_hash(*output, script, script_len);
  return 0;
}

int eth_to_godwoken_addr_gas(const uint8_t* input_src,
                           const size_t input_size,
                           uint64_t* gas) {
  *gas = ETH_TO_GODWOKEN_ADDR_GAS;
  return 0;
}

/* Calculate godwoken short address of an contract account by it's corresponding ETH address

 input:
 ======
   input[12..32] => ETH address

 output:
   output[12..32] => short_gw_script_hash, a.k.a. godwoken short address
 */
int eth_to_godwoken_addr(gw_context_t* ctx,
                         const uint8_t* code_data,
                         const size_t code_size,
                         bool is_static_call,
                         const uint8_t* input_src,
                         const size_t input_size,
                         uint8_t** output, size_t* output_size) {
  if (input_size < 32) {
    debug_print_int("input size too small", input_size);
    return ERROR_ETH_TO_GODWOKEN_ADDR;
  }
  for (int i = 0; i < 12; i++) {
    if (input_src[i] != 0) {
      ckb_debug("invalid ETH address");
      return ERROR_ETH_TO_GODWOKEN_ADDR;
    }
  }
  int ret;
  uint8_t script_args[CONTRACT_ACCOUNT_SCRIPT_ARGS_LEN];
  memcpy(script_args, g_rollup_script_hash, 32);
  memcpy(script_args + 32, (uint8_t*)(&g_creator_account_id), 4);
  memcpy(script_args + 32 + 4, input_src + 12, 20);
  mol_seg_t new_script_seg;
  ret = build_script(g_script_code_hash, g_script_hash_type, script_args,
                     CONTRACT_ACCOUNT_SCRIPT_ARGS_LEN, &new_script_seg);
  if (ret != 0) {
    return ret;
  }
  uint8_t script_hash[32];
  blake2b_hash(script_hash, new_script_seg.ptr, new_script_seg.size);
  free(new_script_seg.ptr);

  *output = (uint8_t *)malloc(32);
  if (*output == NULL) {
    ckb_debug("malloc failed");
    return FATAL_PRECOMPILED_CONTRACTS;
  }
  *output_size = 32;
  memcpy(*output + 12, script_hash, 20);
  return 0;
}

#endif  /* #define OTHER_CONTRACTS_H_ */
