#ifndef POLYJUICE_GLOBALS_H
#define POLYJUICE_GLOBALS_H

#define POLYJUICE_SHORT_ADDR_LEN 20

/* fatal in polyjuice */
#define FATAL_POLYJUICE             -100
#define FATAL_PRECOMPILED_CONTRACTS -101

/* errors in polyjuice */
#define ERROR_MOD_EXP                      -30
#define ERROR_BLAKE2F_INVALID_INPUT_LENGTH -31
#define ERROR_BLAKE2F_INVALID_FINAL_FLAG   -32
#define ERROR_BN256_ADD                    -33
#define ERROR_BN256_SCALAR_MUL             -34
#define ERROR_BN256_PAIRING                -35
#define ERROR_BN256_INVALID_POINT          -36
#define ERROR_BALANCE_OF_ANY_SUDT          -37
#define ERROR_TRANSFER_TO_ANY_SUDT         -38


static uint8_t g_rollup_script_hash[32] = {0};
static uint32_t g_sudt_id = UINT32_MAX;
/* Receipt.contractAddress - The contract address created, if the transaction was a contract creation, otherwise null */
static uint32_t g_created_id = UINT32_MAX;
static uint8_t g_created_address[20] = {0};
static uint32_t g_creator_account_id = UINT32_MAX;
static evmc_address g_tx_origin = {0};
static uint8_t g_script_code_hash[32] = {0};
static uint8_t g_script_hash_type = 0xff;

#endif // POLYJUICE_GLOBALS_H
