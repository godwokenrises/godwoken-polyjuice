
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

evmc_address account_id_to_address(uint32_t account_id) {
  evmc_address addr{0};
  memcpy(addr.bytes, (uint8_t*)(&account_id), 4);
  return addr;
}
int address_to_account_id(const evmc_address* address, uint32_t* account_id) {
  for (size_t i = 4; i < 20; i++) {
    if (address->bytes[i] != 0) {
      /* ERROR: invalid polyjuice address */
      return -1;
    }
  }
  *account_id = *((uint32_t*)(address->bytes));
  return 0;
}

#endif // POLYJUICE_UTILS_H
