
#ifndef SUDT_CONTRACTS_H_
#define SUDT_CONTRACTS_H_

#include "polyjuice_utils.h"

#define BALANCE_OF_ANY_SUDT_GAS 150
#define TRANSFER_TO_ANY_SUDT_GAS 300
#define SET_ALLOWANCE_GAS 150
#define GET_ALLOWANCE_GAS 150
#define TRANSFER_FROM_ANY_SUDT_GAS 450

#define ERROR_BALANCE_OF_ANY_SUDT -30
#define ERROR_TRANSFER_TO_ANY_SUDT -31
#define ERROR_SET_ALLOWANCE -32
#define ERROR_GET_ALLOWANCE -33
#define ERROR_TRANSFER_FROM_ANY_SUDT -34

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
int parse_u128(const uint8_t data_be[32], uint128_t *value) {
  return parse_integer(data_be, (uint8_t *)value, sizeof(uint128_t));
}

/* serialize uint128_t to big endian byte32 */
void put_u128(uint128_t value, uint8_t *output) {
  uint8_t *value_le = (uint8_t *)(&value);
  for (size_t i = 0; i < 16; i++) {
    *(output + 31 - i) = *(value_le + i);
  }
}

int balance_of_any_sudt_gas(const uint8_t* input_src,
                            const size_t input_size,
                            uint64_t* gas) {
  *gas = BALANCE_OF_ANY_SUDT_GAS;
  return 0;
}

/* input:
   ======
     input[ 0..32] => sudt_id (big endian)
     input[32..64] => account_id

   output:
   =======
     output[0..32] => amount
 */
int balance_of_any_sudt(gw_context_t* ctx,
                        uint32_t parent_from_id,
                        bool is_static_call,
                        const uint8_t* input_src,
                        const size_t input_size,
                        uint8_t** output, size_t* output_size) {
  int ret;
  if (input_size != (32 + 32)) {
    return ERROR_BALANCE_OF_ANY_SUDT;
  }

  uint32_t sudt_id = 0;
  ret = parse_u32(input_src, &sudt_id);
  if (ret != 0) {
    return ERROR_BALANCE_OF_ANY_SUDT;
  }

  evmc_address address = *((evmc_address *)(input_src + 32 + 12));
  uint32_t account_id;
  ret = address_to_account_id(&address, &account_id);
  if (ret != 0) {
    ckb_debug("invalid address");
    return ERROR_BALANCE_OF_ANY_SUDT;
  }

  uint128_t balance;
  ret = sudt_get_balance(ctx, sudt_id, account_id, &balance);
  if (ret != 0) {
    ckb_debug("sudt_get_balance failed");
    return ERROR_BALANCE_OF_ANY_SUDT;
  }
  *output = (uint8_t *)malloc(32);
  if (*output == NULL) {
    ckb_debug("malloc failed");
    return -1;
  }
  *output_size = 32;
  memset(*output, 0, 32);
  put_u128(balance, *output);
  return 0;
}

int transfer_to_any_sudt_gas(const uint8_t* input_src,
                             const size_t input_size,
                             uint64_t* gas) {
  *gas = TRANSFER_TO_ANY_SUDT_GAS;
  return 0;
}

/* input:
   ======
     input[ 0..32] => sudt_id (big endian)
     input[32..64] => to_id (address)
     input[64..96] => amount (big endian)

   output: []
 */
int transfer_to_any_sudt(gw_context_t* ctx,
                         uint32_t parent_from_id,
                         bool is_static_call,
                         const uint8_t* input_src,
                         const size_t input_size,
                         uint8_t** output, size_t* output_size) {
  int ret;
  if (is_static_call) {
    ckb_debug("static call to transfer to any sudt is forbidden");
    return ERROR_TRANSFER_TO_ANY_SUDT;
  }
  if (input_size != (32 + 32 + 32)) {
    return ERROR_TRANSFER_TO_ANY_SUDT;
  }

  uint32_t sudt_id = 0;
  uint128_t amount = 0;
  ret = parse_u32(input_src, &sudt_id);
  if (ret != 0) {
    return ERROR_TRANSFER_TO_ANY_SUDT;
  }
  ret = parse_u128(input_src + 64, &amount);
  if (ret != 0) {
    return ERROR_TRANSFER_TO_ANY_SUDT;
  }

  uint32_t to_id = 0;
  evmc_address to_address = *((evmc_address *)(input_src + 32 + 12));
  ret = address_to_account_id(&to_address, &to_id);
  if (ret != 0) {
    ckb_debug("invalid to_address");
    return ERROR_TRANSFER_TO_ANY_SUDT;
  }
  if (parent_from_id == to_id) {
    ckb_debug("parent_from_id can't equals to to_id");
    return ERROR_TRANSFER_TO_ANY_SUDT;
  }
  if (amount == 0) {
    ckb_debug("amount can't be zero");
    return ERROR_TRANSFER_TO_ANY_SUDT;
  }
  ret = sudt_transfer(ctx, sudt_id, parent_from_id, to_id, amount);
  if (ret != 0) {
    ckb_debug("transfer failed");
    return ret;
  }
  *output = NULL;
  *output_size = 0;
  return 0;
}

int set_allowance_gas(const uint8_t* input_src,
                      const size_t input_size,
                      uint64_t* gas) {
  *gas = SET_ALLOWANCE_GAS;
  return 0;
}

/* input:
   ======
   input[ 0..32 ] => sudt_id (big endian)
   input[32..64 ] => spender_id (address)
   input[64..96] => amount (big endian)

   output: []
*/
int set_allowance(gw_context_t* ctx,
                  uint32_t parent_from_id,
                  bool is_static_call,
                  const uint8_t* input_src,
                  const size_t input_size,
                  uint8_t** output, size_t* output_size) {
  int ret = 0;
  if (is_static_call) {
    ckb_debug("static call to set allowance is forbidden");
    return ERROR_SET_ALLOWANCE;
  }
  if (input_size != (32 + 32 + 32)) {
    return ERROR_SET_ALLOWANCE;
  }

  uint32_t sudt_id = 0;
  uint128_t amount = 0;
  ret = parse_u32(input_src, &sudt_id);
  if (ret != 0) {
    return ERROR_SET_ALLOWANCE;
  }
  ret = parse_u128(input_src + 64, &amount);
  if (ret != 0) {
    return ERROR_SET_ALLOWANCE;
  }

  uint32_t spender_id = 0;
  evmc_address spender_address = *((evmc_address *)(input_src + 32 + 12));
  ret = address_to_account_id(&spender_address, &spender_id);
  if (ret != 0) {
    ckb_debug("invalid spender address");
    return ERROR_SET_ALLOWANCE;
  }

  ret = sudt_set_allowance(ctx, sudt_id, parent_from_id, spender_id, amount);
  if (ret != 0) {
    ckb_debug("set allowance failed");
    return ERROR_SET_ALLOWANCE;
  }

  *output = NULL;
  *output_size = 0;
  return 0;
}

int get_allowance_gas(const uint8_t* input_src,
                      const size_t input_size,
                      uint64_t* gas) {
  *gas = GET_ALLOWANCE_GAS;
  return 0;
}

/* input:
   ======
   input[ 0..32] => sudt_id (big endian)
   input[32..64] => owner_id (address)
   input[64..96] => spender_id (address)

   output:
   ========
   output[0..32] => amount (big endian)
*/
int get_allowance(gw_context_t* ctx,
                  uint32_t parent_from_id,
                  bool is_static_call,
                  const uint8_t* input_src,
                  const size_t input_size,
                  uint8_t** output, size_t* output_size) {
  int ret;
  if (input_size != (32 + 32 + 32)) {
    return ERROR_GET_ALLOWANCE;
  }

  uint32_t sudt_id = 0;
  ret = parse_u32(input_src, &sudt_id);
  if (ret != 0) {
    return ERROR_GET_ALLOWANCE;
  }

  uint32_t owner_id = 0;
  uint32_t spender_id = 0;
  evmc_address owner_address = *((evmc_address *)(input_src + 32 + 12));
  evmc_address spender_address = *((evmc_address *)(input_src + 64 + 12));
  ret = address_to_account_id(&owner_address, &owner_id);
  if (ret != 0) {
    ckb_debug("invalid owner address");
    return ERROR_GET_ALLOWANCE;
  }
  ret = address_to_account_id(&spender_address, &spender_id);
  if (ret != 0) {
    ckb_debug("invalid spender address");
    return ERROR_GET_ALLOWANCE;
  }

  uint128_t amount = 0;
  ret = sudt_get_allowance(ctx, sudt_id, owner_id, spender_id, &amount);
  if (ret != 0) {
    ckb_debug("get allowance failed");
    return ERROR_GET_ALLOWANCE;
  }

  *output = (uint8_t *)malloc(32);
  if (*output == NULL) {
    ckb_debug("malloc failed");
    return -1;
  }
  *output_size = 32;
  memset(*output, 0, 32);
  put_u128(amount, *output);
  return 0;
}

int transfer_from_any_sudt_gas(const uint8_t* input_src,
                             const size_t input_size,
                             uint64_t* gas) {
  *gas = TRANSFER_FROM_ANY_SUDT_GAS;
  return 0;
}

/* input:
   ======
     input[ 0..32 ] => sudt_id (big endian)
     input[32..64 ] => sender_id (address)
     input[64..96 ] => recipient_id (address)
     input[96..128] => amount (big endian)

   output: []
 */
int transfer_from_any_sudt(gw_context_t* ctx,
                         uint32_t parent_from_id,
                         bool is_static_call,
                         const uint8_t* input_src,
                         const size_t input_size,
                         uint8_t** output, size_t* output_size) {
  int ret;
  if (is_static_call) {
    ckb_debug("static call to transfer to any sudt is forbidden");
    return ERROR_TRANSFER_FROM_ANY_SUDT;
  }
  if (input_size != (32 + 32 + 32 + 32)) {
    return ERROR_TRANSFER_FROM_ANY_SUDT;
  }

  uint32_t sudt_id = 0;
  uint128_t amount = 0;
  ret = parse_u32(input_src, &sudt_id);
  if (ret != 0) {
    return ERROR_TRANSFER_FROM_ANY_SUDT;
  }
  ret = parse_u128(input_src + 96, &amount);
  if (ret != 0) {
    return ERROR_TRANSFER_FROM_ANY_SUDT;
  }

  uint32_t sender_id = 0;
  uint32_t recipient_id = 0;
  evmc_address sender_address = *((evmc_address *)(input_src + 32 + 12));
  evmc_address recipient_address = *((evmc_address *)(input_src + 64 + 12));
  ret = address_to_account_id(&sender_address, &sender_id);
  if (ret != 0) {
    ckb_debug("invalid sender address");
    return ERROR_TRANSFER_FROM_ANY_SUDT;
  }
  ret = address_to_account_id(&recipient_address, &recipient_id);
  if (ret != 0) {
    ckb_debug("invalid recipient address");
    return ERROR_TRANSFER_FROM_ANY_SUDT;
  }

  if (sender_id == 0) {
    ckb_debug("approve from zero address");
    return ERROR_TRANSFER_FROM_ANY_SUDT;
  }
  if (parent_from_id == 0) {
    ckb_debug("approve to zero address");
    return ERROR_TRANSFER_FROM_ANY_SUDT;
  }

  uint128_t current_allowance = 0;
  ret = sudt_get_allowance(ctx, sudt_id, sender_id, parent_from_id, &current_allowance);
  if (ret != 0) {
    ckb_debug("sudt get allowance failed");
    return ERROR_TRANSFER_FROM_ANY_SUDT;
  }
  if (current_allowance < amount) {
    ckb_debug("transfer amount exceeds allowance");
    return ERROR_TRANSFER_FROM_ANY_SUDT;
  }
  ret = sudt_set_allowance(ctx, sudt_id, sender_id, parent_from_id, current_allowance - amount);
  if (ret != 0) {
    ckb_debug("sudt set allowance failed");
    return ERROR_TRANSFER_FROM_ANY_SUDT;
  }

  ret = sudt_transfer(ctx, sudt_id, sender_id, recipient_id, amount);
  if (ret != 0) {
    ckb_debug("sudt transfer failed");
    return ERROR_TRANSFER_FROM_ANY_SUDT;
  }

  *output = NULL;
  *output_size = 0;
  return 0;
}
#endif
