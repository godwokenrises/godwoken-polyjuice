#ifndef POLYJUICE_GLOBALS_H
#define POLYJUICE_GLOBALS_H

#define POLYJUICE_VERSION "v0.8.10"
#define POLYJUICE_SHORT_ADDR_LEN 20
/* 32 + 4 + 20 */
#define SCRIPT_ARGS_LEN 56

static uint8_t g_rollup_script_hash[32] = {0};
static uint32_t g_sudt_id = UINT32_MAX;

static bool g_is_using_native_eth_address = false;
/** 
 * Receipt.contractAddress
 * The contract address created, if the transaction was a contract creation,
 * otherwise null
 */
static uint32_t g_created_id = UINT32_MAX;
static uint8_t g_created_address[20] = {0};

static uint32_t g_creator_account_id = UINT32_MAX;
static evmc_address g_tx_origin = {0};

static uint8_t g_script_code_hash[32] = {0};
static uint8_t g_script_hash_type = 0xff;

#endif // POLYJUICE_GLOBALS_H
