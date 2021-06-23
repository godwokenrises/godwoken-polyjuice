/* note, this macro should be same as in ckb_syscall.h */
#ifndef CKB_C_STDLIB_CKB_SYSCALLS_H_
#define CKB_C_STDLIB_CKB_SYSCALLS_H_
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "ckb_consts.h"

int ckb_debug(const char* s) {
  printf("[debug] %s\n", s);
  return 0;
}

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
  if (n == 4051) { // GW_SYS_LOAD_TRANSACTION = 4051
    ckb_debug("GW_SYS_LOAD_TRANSACTION");
    // if ((content_size <= memory_size) &&
    //     (content_offset + content_size < s_INPUT_SIZE) &&
    //     (content_offset <= content_offset + content_size)) {
    //   memcpy(addr, s_INPUT_DATA + content_offset, content_size);
    // }
    // FIXME:
    // *_a1 = (uint64_t)0;
    // (uint64_t)*_a1 = 0;
    return CKB_SUCCESS;
  } else if (n == SYS_ckb_load_cell_data_as_code) {
    ckb_debug("TODO: SYS_ckb_load_cell_data_as_code");
    return CKB_INVALID_DATA;
    // return ckb_load_cell_data_as_code((void*)_a0, (size_t)_a1, (size_t)_a2,
    //                                   (size_t)_a3, (size_t)_a4, (size_t)_a5);
  } else {
    return CKB_INVALID_DATA;
  }
}
#endif

#ifdef GW_GENERATOR
#include "mock_generator_utils.h"
#endif
