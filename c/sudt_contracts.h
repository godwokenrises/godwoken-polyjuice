
#ifndef SUDT_CONTRACTS_H_
#define SUDT_CONTRACTS_H_

#include "polyjuice_utils.h"

#define BALANCE_OF_ANY_SUDT_GAS 150
#define TRANSFER_TO_ANY_SUDT_GAS 300

#define ERROR_BALANCE_OF_ANY_SUDT -30
#define ERROR_TRANSFER_TO_ANY_SUDT -31

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

/*
  Query the balance of `account_id` of `sudt_id` token.

   input:
   ======
     input[ 0..32] => sudt_id (big endian)
     input[32..64] => account_id

   output:
   =======
     output[0..32] => amount
 */
int balance_of_any_sudt(gw_context_t* ctx,
                        const uint8_t* code_data,
                        const size_t code_size,
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
  ret = address_to_account_id(ctx, &address, &account_id);
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

/*
  Transfer `sudt_id` token from `from_id` to `to_id` with `amount` balance.

  NOTE: This pre-compiled contract need caller to check permission of `from_id`,
  currently only `solidity/erc20/SudtERC20Proxy.sol` is allowed to call this contract.

   input:
   ======
     input[ 0..32 ] => sudt_id (big endian)
     input[32..64 ] => from_id (address)
     input[64..96 ] => to_id (address)
     input[96..128] => amount (big endian)

   output: []
 */
int transfer_to_any_sudt(gw_context_t* ctx,
                         const uint8_t* code_data,
                         const size_t code_size,
                         bool is_static_call,
                         const uint8_t* input_src,
                         const size_t input_size,
                         uint8_t** output, size_t* output_size) {

  /* Contract code hash of `SudtERC20Proxy.sol`
     => 0x84fca35d11d31b80bd6b49e62450307af842bed3d61232fe90af6d555ad93aa5 */
  static const uint8_t sudt_erc20_proxy_contract_code_hash[32] =
    {
     0x84, 0xfc, 0xa3, 0x5d, 0x11, 0xd3, 0x1b, 0x80,
     0xbd, 0x6b, 0x49, 0xe6, 0x24, 0x50, 0x30, 0x7a,
     0xf8, 0x42, 0xbe, 0xd3, 0xd6, 0x12, 0x32, 0xfe,
     0x90, 0xaf, 0x6d, 0x55, 0x5a, 0xd9, 0x3a, 0xa5,
    };
  if (code_data == NULL || code_size == 0) {
    ckb_debug("Invalid caller contract code");
    return ERROR_TRANSFER_TO_ANY_SUDT;
  }
  uint8_t code_hash[32] = {0};
  blake2b_hash(code_hash, (uint8_t *)code_data, code_size);
  if (memcmp(code_hash, sudt_erc20_proxy_contract_code_hash, 32) != 0) {
    ckb_debug("The contract is not allowed to call transfer_to_any_sudt");
    return ERROR_TRANSFER_TO_ANY_SUDT;
  }

  int ret;
  if (is_static_call) {
    ckb_debug("static call to transfer to any sudt is forbidden");
    return ERROR_TRANSFER_TO_ANY_SUDT;
  }
  if (input_size != (32 + 32 + 32 + 32)) {
    return ERROR_TRANSFER_TO_ANY_SUDT;
  }

  uint32_t sudt_id = 0;
  uint128_t amount = 0;
  ret = parse_u32(input_src, &sudt_id);
  if (ret != 0) {
    return ERROR_TRANSFER_TO_ANY_SUDT;
  }
  ret = parse_u128(input_src + 96, &amount);
  if (ret != 0) {
    return ERROR_TRANSFER_TO_ANY_SUDT;
  }

  uint32_t from_id = 0;
  evmc_address from_address = *((evmc_address *)(input_src + 32 + 12));
  ret = address_to_account_id(ctx, &from_address, &from_id);
  if (ret != 0) {
    ckb_debug("invalid from_address");
    return ERROR_TRANSFER_TO_ANY_SUDT;
  }

  uint32_t to_id = 0;
  evmc_address to_address = *((evmc_address *)(input_src + 64 + 12));
  ret = address_to_account_id(ctx, &to_address, &to_id);
  if (ret != 0) {
    ckb_debug("invalid to_address");
    return ERROR_TRANSFER_TO_ANY_SUDT;
  }

  if (from_id == to_id) {
    ckb_debug("from_id can't equals to to_id");
    return ERROR_TRANSFER_TO_ANY_SUDT;
  }
  if (amount == 0) {
    ckb_debug("amount can't be zero");
    return ERROR_TRANSFER_TO_ANY_SUDT;
  }
  ret = sudt_transfer(ctx, sudt_id, from_id, to_id, amount);
  if (ret != 0) {
    ckb_debug("transfer failed");
    return ret;
  }
  *output = NULL;
  *output_size = 0;
  return 0;
}
#endif

