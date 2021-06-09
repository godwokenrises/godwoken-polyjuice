
#ifndef OTHER_CONTRACTS_H_
#define OTHER_CONTRACTS_H_

#include "polyjuice_utils.h"
#include "polyjuice_globals.h"

/* Gas fee */
#define RECOVER_ACCOUNT_GAS 3600 /* more than ecrecover */

/* Errors */
#define ERROR_RECOVER_ACCOUNT -40

int recover_account_gas(const uint8_t* input_src,
                        const size_t input_size,
                        uint64_t* gas) {
  *gas = RECOVER_ACCOUNT_GAS;
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
int recover_account(gw_context_t* ctx,
                    const uint8_t* code_data,
                    const size_t code_size,
                    bool is_static_call,
                    const uint8_t* input_src,
                    const size_t input_size,
                    uint8_t** output, size_t* output_size) {

  if (input_size != 64) {
    debug_print_int("eth to polyjuice address: invalid input length", input_size);
    return ERROR_RECOVER_ACCOUNT;
  }
  return 0;
}

#endif  /* #define OTHER_CONTRACTS_H_ */
