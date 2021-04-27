
#ifndef POLYJUICE_UTILS_H
#define POLYJUICE_UTILS_H

#include <stddef.h>
#include <stdint.h>

#include <evmc/evmc.h>
#include "ckb_syscalls.h"

#ifdef NO_DEBUG_LOG
#undef ckb_debug
#define ckb_debug(s) {}
#define debug_print(s) {}
#define debug_print_int(prefix, value) {}
#define debug_print_data(prefix, data, data_len) {}
#else  /* #ifdef NO_DEBUG_LOG */
static char debug_buffer[64 * 1024];
void debug_print_data(const char* prefix, const uint8_t* data,
                             uint32_t data_len) {
  int offset = 0;
  offset += sprintf(debug_buffer, "%s 0x", prefix);
  for (size_t i = 0; i < data_len; i++) {
    offset += sprintf(debug_buffer + offset, "%02x", data[i]);
  }
  debug_buffer[offset] = '\0';
  ckb_debug(debug_buffer);
}
void debug_print_int(const char* prefix, int64_t ret) {
  sprintf(debug_buffer, "%s => %ld", prefix, ret);
  ckb_debug(debug_buffer);
}
#endif  /* #ifdef NO_DEBUG_LOG */

/*
  eth_address[ 0..16] = script_hash[0..16]
  eth_address[16..20] = account_id (little endian)
 */
int account_id_to_address(gw_context_t* ctx, uint32_t account_id, evmc_address *addr) {
  if (account_id == 0) {
    memset(addr->bytes, 0, 20);
    return 0;
  }

  uint8_t script_hash[32] = {0};
  int ret = ctx->sys_get_script_hash_by_account_id(ctx, account_id, script_hash);
  if (ret != 0) {
    debug_print_int("get script hash by account id failed", account_id);
    return ret;
  }

  memcpy(addr->bytes, script_hash, 16);
  memcpy(addr->bytes + 16, (uint8_t*)(&account_id), 4);
  return 0;
}

/*
  Must check eth_address[0..16] match the script_hash[0..16] of the account id
 */
int address_to_account_id(gw_context_t* ctx, const evmc_address* address, uint32_t* account_id) {
  /* Zero address is special case */
  static uint8_t zero_address[20] = {0};
  if (memcmp(address->bytes, zero_address, 20) == 0) {
    *account_id = 0;
    return 0;
  }

  *account_id = *((uint32_t*)(address->bytes + 16));
  uint8_t script_hash[32] = {0};
  int ret = ctx->sys_get_script_hash_by_account_id(ctx, *account_id, script_hash);
  if (ret != 0) {
    debug_print_int("get script hash by account id failed", *account_id);
    return ret;
  }
  if (memcmp(address->bytes, script_hash, 16) != 0) {
    debug_print_data("check script hash failed, invalid eth address", address->bytes, 20);
    return -1;
  }
  return 0;
}

#endif // POLYJUICE_UTILS_H
