
#ifndef POLYJUICE_UTILS_H
#define POLYJUICE_UTILS_H

#include <stddef.h>
#include <stdint.h>

#include <evmc/evmc.h>

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
