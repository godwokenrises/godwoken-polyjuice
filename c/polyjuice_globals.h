#ifndef POLYJUICE_GLOBALS_H
#define POLYJUICE_GLOBALS_H

#define POLYJUICE_VERSION "v1.0.0"

/** TODO: rename to DEFAULT_SHORT_SCRIPT_HASH_LEN */
#define POLYJUICE_SHORT_ADDR_LEN 20
#define ETH_ADDRESS_LEN 20

#define GW_ETH_ADDRESS_TO_ACCOUNT_SCRIPT_HASH 6
#define GW_ACCOUNT_SCRIPT_HASH_TO_ETH_ADDRESS 7

/** Polyjuice contract account (normal/create2) script args size */
#define CONTRACT_ACCOUNT_SCRIPT_ARGS_LEN 56       /* 32 + 4 + 20 */

static uint8_t g_rollup_script_hash[32] = {0};
static uint32_t g_sudt_id = UINT32_MAX;

static bool g_is_using_native_eth_address = false;
/** 
 * Receipt.contractAddress is the created contract,
 * if the transaction was a contract creation, otherwise null
 */
static uint8_t g_created_address[20] = {0};
static uint32_t g_created_id = UINT32_MAX;

/**
 * creator_account, known as root account
 * see also: https://github.com/nervosnetwork/godwoken/blob/5735d8f/docs/life_of_a_polyjuice_transaction.md#root-account--deployment
 */
static uint32_t g_creator_account_id = UINT32_MAX;

static evmc_address g_tx_origin = {0};

static uint8_t g_script_code_hash[32] = {0};
static uint8_t g_script_hash_type = 0xff;

#endif // POLYJUICE_GLOBALS_H
