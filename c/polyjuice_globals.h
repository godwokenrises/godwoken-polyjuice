#ifndef POLYJUICE_GLOBALS_H
#define POLYJUICE_GLOBALS_H

#define POLYJUICE_VERSION "v0.8.14"
#define POLYJUICE_SHORT_ADDR_LEN 20
/* 32 + 4 + 20 */
#define SCRIPT_ARGS_LEN 56

static uint8_t g_rollup_script_hash[32] = {0};
static uint32_t g_sudt_id = UINT32_MAX;

/**
 * Receipt.contractAddress is the created contract,
 * if the transaction was a contract creation, otherwise null
 */
static uint32_t g_created_id = UINT32_MAX;
static uint8_t g_created_address[20] = {0};

/**
 * creator_account, known as root account
 * @see https://github.com/nervosnetwork/godwoken/blob/develop/docs/life_of_a_polyjuice_transaction.md#root-account--deployment
 */
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
#define TESTNET_V0_FORK1_BLOCK 380000
bool is_testnet_v0() {
  // Godwoken testnet_v0 Rollup script hash:
  // 0x4cc2e6526204ae6a2e8fcf12f7ad472f41a1606d5b9624beebd215d780809f6a
  static const uint8_t testnet_v0_rollup_script_hash[32] = {
    0x4c, 0xc2, 0xe6, 0x52, 0x62, 0x04, 0xae, 0x6a,
    0x2e, 0x8f, 0xcf, 0x12, 0xf7, 0xad, 0x47, 0x2f,
    0x41, 0xa1, 0x60, 0x6d, 0x5b, 0x96, 0x24, 0xbe,
    0xeb, 0xd2, 0x15, 0xd7, 0x80, 0x80, 0x9f, 0x6a
  };

  return 0 == memcmp(g_rollup_script_hash, testnet_v0_rollup_script_hash, 32);
}

#endif // POLYJUICE_GLOBALS_H
