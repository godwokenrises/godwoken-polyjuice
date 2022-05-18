#ifndef POLYJUICE_GLOBALS_H
#define POLYJUICE_GLOBALS_H

#define POLYJUICE_VERSION "v0.8.13"
#define POLYJUICE_SHORT_ADDR_LEN 20
/* 32 + 4 + 20 */
#define SCRIPT_ARGS_LEN 56

static uint8_t g_rollup_script_hash[32] = {0};
static uint32_t g_sudt_id = UINT32_MAX;
/* Receipt.contractAddress - The contract address created, if the transaction was a contract creation, otherwise null */
static uint32_t g_created_id = UINT32_MAX;
static uint8_t g_created_address[20] = {0};
static uint32_t g_creator_account_id = UINT32_MAX;
static evmc_address g_tx_origin = {0};
static uint8_t g_script_code_hash[32] = {0};
static uint8_t g_script_hash_type = 0xff;

/**
 * @brief Hardforks
 * 
 * TESTNET_V0_FORK1
 *   fix: CALLCODE and DELEGATECALL should skip transfer
 *   https://github.com/nervosnetwork/godwoken-polyjuice/commit/c927fb6ce6d5c3632e09bc5de2d1485736c56fe0
 */
#define TESTNET_V0_CHAIN_ID     71393
#define TESTNET_V0_FORK1_BLOCK 380000

#endif // POLYJUICE_GLOBALS_H
