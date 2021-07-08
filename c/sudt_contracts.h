
#ifndef SUDT_CONTRACTS_H_
#define SUDT_CONTRACTS_H_

#include "polyjuice_utils.h"
#include "polyjuice_globals.h"

#define BALANCE_OF_ANY_SUDT_GAS 150
#define TRANSFER_TO_ANY_SUDT_GAS 300

#define ERROR_BALANCE_OF_ANY_SUDT -30
#define ERROR_TRANSFER_TO_ANY_SUDT -31


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
     input[32..64] => address (short_address)

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
  uint128_t balance;
  ret = sudt_get_balance(ctx, sudt_id, POLYJUICE_SHORT_ADDR_LEN, address.bytes, &balance);
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
     input[32..64 ] => from_addr (short address)
     input[64..96 ] => to_addr (short address)
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
     => 0x43a008ec973b648bd71ad67e6b66f2be8a6fa88e89c7dad046c948b00aa866aa */
  static const uint8_t sudt_erc20_proxy_contract_code_hash[32] =
    {
      0x43, 0xa0, 0x08, 0xec, 0x97, 0x3b, 0x64, 0x8b,
      0xd7, 0x1a, 0xd6, 0x7e, 0x6b, 0x66, 0xf2, 0xbe,
      0x8a, 0x6f, 0xa8, 0x8e, 0x89, 0xc7, 0xda, 0xd0,
      0x46, 0xc9, 0x48, 0xb0, 0x0a, 0xa8, 0x66, 0xaa,
    };
  if (code_data == NULL || code_size == 0) {
    ckb_debug("Invalid caller contract code");
    return ERROR_TRANSFER_TO_ANY_SUDT;
  }
  uint8_t code_hash[32] = {0};
  blake2b_hash(code_hash, (uint8_t *)code_data, code_size);
  if (memcmp(code_hash, sudt_erc20_proxy_contract_code_hash, 32) != 0) {
    ckb_debug("The contract is not allowed to call transfer_to_any_sudt");
    debug_print_data("     got code hash", code_hash, 32);
    debug_print_data("expected code hash", sudt_erc20_proxy_contract_code_hash, 32);
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

  evmc_address from_address = *((evmc_address *)(input_src + 32 + 12));
  evmc_address to_address = *((evmc_address *)(input_src + 64 + 12));
  ret = sudt_transfer(ctx, sudt_id, POLYJUICE_SHORT_ADDR_LEN, from_address.bytes, to_address.bytes, amount);
  if (ret != 0) {
    ckb_debug("transfer failed");
    return ret;
  }
  *output = NULL;
  *output_size = 0;
  return 0;
}

#endif  /* #define SUDT_CONTRACTS_H_ */

