/**
 * `ETH Address Registry` layer2 contract
 * 
 * This contract introduces two-ways mappings between `eth_address` and
 * `gw_script_hash`.
 * 
 *   - `eth_address` is the address of an Ethereum EOA (externally owned account
 *     ) or a Polyjuice contract account.
 * 
 *   - Godwoken account script hash(a.k.a. `gw_script_hash`) is a key used for
 *     locating the account lock. Godwoken enforces one-to-one mapping between 
 *     layer 2 lock script and accountID.
 */

#include "gw_syscalls.h"
#include "polyjuice_utils.h"
#include "sudt_utils.h"

/* MSG_TYPE */
#define MSG_QUERY_GW_BY_ETH 0
#define MSG_QUERY_ETH_BY_GW 1
#define MSG_SET_MAPPING     2

int handle_fee(gw_context_t *ctx, mol_seg_t fee_seg) {
  if (ctx == NULL) {
    return GW_FATAL_INVALID_CONTEXT;
  }

  /* payer's short address */
  uint8_t payer_account_script_hash[32] = {0};
  int ret = ctx->sys_get_script_hash_by_account_id(
      ctx, ctx->transaction_context.from_id, payer_account_script_hash);
  if (ret != 0) {
    return ret;
  }
  uint64_t short_script_hash_len = DEFAULT_SHORT_SCRIPT_HASH_LEN;
  /* sudt */
  mol_seg_t sudt_id_seg = MolReader_Fee_get_sudt_id(&fee_seg);
  uint32_t sudt_id = *(uint32_t *)sudt_id_seg.ptr;
  /* amount */
  mol_seg_t amount_seg = MolReader_Fee_get_amount(&fee_seg);
  uint128_t amount = *(uint128_t *)amount_seg.ptr;
  return sudt_pay_fee(ctx, sudt_id, short_script_hash_len,
                      payer_account_script_hash, amount);
}

int main() {
#ifdef CKB_C_STDLIB_PRINTF
  // init buffer for debug_print
  char buffer[DEBUG_BUFFER_SIZE];
  g_debug_buffer = buffer;
#endif
  ckb_debug("====== ETH Address Registry ======");

  /* initialize context */
  gw_context_t ctx = {0};
  int ret = gw_context_init(&ctx);
  if (ret != 0) {
    return ret;
  };

  /* verify and parse args */
  mol_seg_t args_seg;
  args_seg.ptr = ctx.transaction_context.args;
  args_seg.size = ctx.transaction_context.args_len;
  if (MolReader_ETHAddrRegArgs_verify(&args_seg, false) != MOL_OK) {
    return GW_FATAL_INVALID_DATA;
  }
  mol_union_t msg = MolReader_ETHAddrRegArgs_unpack(&args_seg);

  /* handle message */
  if (msg.item_id == MSG_QUERY_GW_BY_ETH) {
    mol_seg_t eth_address_seg = MolReader_EthToGw_get_eth_address(&msg.seg);
    uint8_t script_hash[GW_VALUE_BYTES] = {0};
    ret = load_script_hash_by_eth_address(&ctx,
                                          eth_address_seg.ptr,
                                          script_hash);
    if (ret != 0) {
      return ret;
    }
    ret = ctx.sys_set_program_return_data(&ctx, script_hash, GW_VALUE_BYTES);
    if (ret != 0) {
      return ret;
    }
  }
  else if (msg.item_id == MSG_QUERY_ETH_BY_GW) {
    mol_seg_t script_hash_seg = MolReader_GwToEth_get_gw_script_hash(&msg.seg);
    uint8_t eth_address[ETH_ADDRESS_LEN] = {0};
    ret = load_eth_address_by_script_hash(&ctx,
                                          script_hash_seg.ptr,
                                          eth_address);
    if (ret != 0) {
      return ret;
    }
    ret = ctx.sys_set_program_return_data(&ctx, eth_address, ETH_ADDRESS_LEN);
    if (ret != 0) {
      return ret;
    }
  }
  else if (msg.item_id == MSG_SET_MAPPING) {
    /* charge fee */
    mol_seg_t fee_seg = MolReader_SetMapping_get_fee(&msg.seg);
    ret = handle_fee(&ctx, fee_seg);
    if (ret != 0) {
      return ret;
    }

    mol_seg_t script_hash_seg = MolReader_SetMapping_get_gw_script_hash(&msg.seg);
    ret = eth_address_register(&ctx, script_hash_seg.ptr);
    if (ret != 0) {
      return ret;
    }
  }
  else {
    return GW_FATAL_UNKNOWN_ARGS;
  }

  return gw_finalize(&ctx);
}
