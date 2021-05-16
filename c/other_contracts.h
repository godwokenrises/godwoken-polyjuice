
#ifndef OTHER_CONTRACTS_H_
#define OTHER_CONTRACTS_H_

#include "polyjuice_utils.h"
#include "polyjuice_globals.h"

/* Gas fee */
#define ETH_TO_POLYJUICE_ADDR_GAS 200

/* Errors */
#define ERROR_ETH_TO_POLYJUICE_ADDR -40

int eth_to_polyjuice_address_gas(const uint8_t* input_src,
                                    const size_t input_size,
                                    uint64_t* gas) {
  *gas = ETH_TO_POLYJUICE_ADDR_GAS;
  return 0;
}

/*
  Calculate polyjuice from ETH address.

  input:
  ======
    input[ 0..32] => EoA account lock code hash (assume hash type must `type`)
    input[32..64] => ETH address

  output:
  =======
    output[0..32] => polyjuice address (blake128 + account id)
 */
int eth_to_polyjuice_address(gw_context_t* ctx,
                             const uint8_t* code_data,
                             const size_t code_size,
                             bool is_static_call,
                             const uint8_t* input_src,
                             const size_t input_size,
                             uint8_t** output, size_t* output_size) {

  if (input_size != 64) {
    debug_print_int("eth to polyjuice address: invalid input length", input_size);
    return ERROR_ETH_TO_POLYJUICE_ADDR;
  }

  int ret;
  uint8_t eoa_lock_code_hash[32] = {0};
  memcpy(eoa_lock_code_hash, input_src, 32);

  /* ScriptHashType::Type = 1 */
  static const uint8_t script_hash_type = 1;
  static const uint32_t script_args_len = 32 + 20;
  uint8_t script_args[script_args_len] = {0};
  memcpy(script_args, g_rollup_script_hash, 32);
  memcpy(script_args + 32, input_src + 32 + 12, 20);
  mol_seg_t new_script_seg;
  ret = build_script(eoa_lock_code_hash, script_hash_type, script_args, script_args_len, &new_script_seg);
  if (ret != 0) {
    debug_print_int("eth to polyjuice address: build script failed", ret);
    return ERROR_ETH_TO_POLYJUICE_ADDR;
  }

  uint8_t script_hash[32] = {0};
  blake2b_hash(script_hash, new_script_seg.ptr, new_script_seg.size);
  free(new_script_seg.ptr);
  uint32_t account_id = 0;
  ret = ctx->sys_get_account_id_by_script_hash(ctx, script_hash, &account_id);
  if (ret != 0) {
    debug_print_int("eth to polyjuice address: get account id failed", ret);
    return ERROR_ETH_TO_POLYJUICE_ADDR;
  }

  *output = (uint8_t *)malloc(32);
  if (*output == NULL) {
    ckb_debug("eth to polyjuice address: malloc output failed");
    return ERROR_ETH_TO_POLYJUICE_ADDR;
  }
  memset(*output, 0, 12);
  memcpy(*output + 12, script_hash, 16);
  memcpy(*output + 12 + 16, (uint8_t *)(&account_id), 4);
  *output_size = 32;
  return 0;
}

#endif  /* #define OTHER_CONTRACTS_H_ */
