/* note, this macro should be same as in ckb_syscall.h */
#ifndef CKB_C_STDLIB_CKB_SYSCALLS_H_
#define CKB_C_STDLIB_CKB_SYSCALLS_H_
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "ckb_consts.h"

size_t s_INPUT_SIZE = 0;
uint8_t* s_INPUT_DATA = NULL;

int ckb_debug(const char* str) {
  printf("[debug] %s\n", str);
  return 0;
}

static char debug_buf[64 * 1024];
void dbg_print(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vsnprintf(debug_buf, sizeof(debug_buf), fmt, args);
    va_end(args);
    ckb_debug(debug_buf);
}

#ifdef NO_DEBUG_LOG
#undef ckb_debug
#undef debug_print
#define ckb_debug(s) do {} while (0)
#define debug_print(...) do {} while (0)
#endif

int ckb_exit(int8_t code) {
  printf("ckb_exit, code=%d\n", code);
  exit(0);
  return CKB_SUCCESS;
}

int ckb_load_tx_hash(void* addr, uint64_t* len, size_t offset);

int ckb_load_script_hash(void* addr, uint64_t* len, size_t offset);

int ckb_load_cell(void* addr, uint64_t* len, size_t offset, size_t index,
                  size_t source);

int ckb_load_cell_data_as_code(void* addr, size_t memory_size,
                               size_t content_offset, size_t content_size,
                               size_t index, size_t source);

int ckb_load_input(void* addr, uint64_t* len, size_t offset, size_t index,
                   size_t source);

int ckb_load_header(void* addr, uint64_t* len, size_t offset, size_t index,
                    size_t source);

int ckb_load_witness(void* addr, uint64_t* len, size_t offset, size_t index,
                     size_t source);

int ckb_load_script(void* addr, uint64_t* len, size_t offset);

int ckb_load_cell_by_field(void* addr, uint64_t* len, size_t offset,
                           size_t index, size_t source, size_t field);

int ckb_load_header_by_field(void* addr, uint64_t* len, size_t offset,
                             size_t index, size_t source, size_t field);

int ckb_load_input_by_field(void* addr, uint64_t* len, size_t offset,
                            size_t index, size_t source, size_t field);

int ckb_load_cell_code(void* addr, size_t memory_size, size_t content_offset,
                       size_t content_size, size_t index, size_t source);

int ckb_load_cell_data(void* addr, uint64_t* len, size_t offset, size_t index,
                       size_t source);

int load_actual_type_witness(uint8_t* buf, uint64_t* len, size_t index,
                             size_t* type_source);

int ckb_look_for_dep_with_hash(const uint8_t* data_hash, size_t* index);

int ckb_calculate_inputs_len();

int ckb_look_for_dep_with_hash2(const uint8_t* code_hash, uint8_t hash_type,
                                size_t* index);

int ckb_checked_load_cell_by_field(void* addr, uint64_t* len, size_t offset,
                                   size_t index, size_t source, size_t field);

int ckb_checked_load_cell_data(void* addr, uint64_t* len, size_t offset,
                               size_t index, size_t source);

int ckb_checked_load_witness(void* addr, uint64_t* len, size_t offset,
                             size_t index, size_t source);

int ckb_checked_load_script(void* addr, uint64_t* len, size_t offset);

// Mock implementation for the SYS_ckb_load_cell_data_as_code syscall in
// _ckb_load_cell_code.
#define syscall(n, a0, a1, a2, a3, a4, a5)                              \
  __internal_syscall(n, (long)(a0), (long)(a1), (long)(a2), (long)(a3), \
                     (long)(a4), (long)(a5))

static int inline __internal_syscall(long n, long _a0, long _a1, long _a2,
                                     long _a3, long _a4, long _a5) {
  const uint8_t account_2_key[] = {2, 0, 0, 0, 255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  const uint8_t account_3_key[] = {3, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  const uint8_t account_4_key[] = {4, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

  switch (n) {
    case 3102: // GW_SYS_LOAD = 3102
      dbg_print("Mock __internal_syscall(GW_SYS_LOAD)");
      if (0 == memcmp(account_2_key, (uint8_t*)_a0, sizeof(account_2_key))
       || 0 == memcmp(account_3_key, (uint8_t*)_a0, sizeof(account_3_key))
       || 0 == memcmp(account_4_key, (uint8_t*)_a0, sizeof(account_3_key))
      ) {
        memset((uint8_t*)_a1, 0, 32);
        return CKB_SUCCESS;
      }
      return CKB_INVALID_DATA;
    default:
      return CKB_INVALID_DATA;
  }
}
#endif

#ifdef GW_GENERATOR
#include "mock_generator_utils.h"
#endif
