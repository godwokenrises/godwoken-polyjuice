#include <evmone/evmone.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

#include "api.h"
#include "ckb_syscalls.h"
#define GW_GENERATOR
#define CKB_C_STDLIB_CKB_SYSCALLS_H_
#define CREATOR_ID 1
#define CHAIN_ID 1
#include "polyjuice.h"
#include "godwoken.h"

inline evmc::address generate_interesting_address(uint8_t b) noexcept
{
    const auto s = (b >> 6) & 0b11;
    const auto fill = (b >> 5) & 0b1;
    const auto above = (b >> 4) & 0b1;
    const auto val = b & 0b1111;

    auto z = evmc::address{};

    const size_t size = s == 3 ? 20 : 1 << s;

    if (fill)
    {
        for (auto i = sizeof(z) - size; i < sizeof(z); ++i)
            z.bytes[i] = 0xff;
    }

    if (above)
        z.bytes[sizeof(z) - size % sizeof(z) - 1] ^= val;
    else
        z.bytes[sizeof(z) - size] ^= val << 4;

    return z;
}

mol_seg_t build_Bytes(uint8_t* ptr, uint32_t len) {
  mol_builder_t b;
  mol_seg_res_t res;
  MolBuilder_Bytes_init(&b);
  for (uint32_t i = 0; i < len; i++) {
    MolBuilder_Bytes_push(&b, ptr[i]);
  }
  res = MolBuilder_Bytes_build(b);
  return res.seg;
}


void init_polyjuice_tx(mol_builder_t *b) {
  uint64_t chain_id = 1;
  MolBuilder_RawL2Transaction_set_chain_id(b, (uint8_t*)(&chain_id), 8);
  uint32_t from_id = 32;
  MolBuilder_RawL2Transaction_set_from_id(b, (uint8_t*)(&from_id), 4);
  uint32_t to_id = 12;
  MolBuilder_RawL2Transaction_set_to_id(b, (uint8_t*)(&to_id), 4);
  uint32_t nonce = 0;
  MolBuilder_RawL2Transaction_set_nonce(b, (uint8_t*)(&nonce), 4);
  uint8_t prefix[7] = {0xFF, 0xFF, 0xFF, 'P', 'O', 'L', 'Y'};
  uint8_t args[7+1+8+16+16+4+MAX_DATA_SIZE];
  memcpy(args, prefix, 7); // prefix POLY
  args[7] = 3; // EVMC_CREATE
  uint32_t args_offset = 8;
  uint64_t gas_limit = 210000;
  memcpy(args+args_offset, &gas_limit, 8); // gas
  args_offset += 8;
  uint128_t gas_price = 10;
  memcpy(args+args_offset, &gas_price, 16); // gas_price
  args_offset += 16;
  uint128_t value = 0;
  memcpy(args+args_offset, &value, 16); // value
  args_offset += 16;
  uint32_t len = 0;
  memcpy(args+args_offset, &len, 4);

  mol_seg_t bytes = build_Bytes(args, args_offset);
  MolBuilder_RawL2Transaction_set_args(b, bytes.ptr, bytes.size);
}

extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {

  if (size < 108) {
    return -1; 
  }
  gw_reset();
  uint8_t kind = ((data[0] >> 3) & 0b1) == 0 ? 0 : 3; // call: 0; create: 1
  uint8_t native_transfer = (data[1] >> 3) & 0b1; // 1: native transfer tag
  
  evmc::address from_addr = generate_interesting_address(data[2]);
  evmc::address to_addr = generate_interesting_address(data[3]);
  evmc::address transfer_to = generate_interesting_address(data[4]);

  // mock from_id
  int offset = 5;
  uint8_t mint[16] = {0};
  memcpy(mint, data + offset, 16);
  offset += 16;
  uint32_t from_id;
  gw_create_eoa_account(from_addr.bytes, mint, &from_id);

  uint32_t to_id;
  if (kind == 0) { //mock to_id by creating contract account with code
    gw_create_contract_account(to_addr.bytes, mint, data, size, &to_id);
  } else {
    to_id = CREATOR_ID;
  }

  uint8_t gas_price[16] = {0};
  memcpy(gas_price, data + offset, 16);
  offset += 16;
  uint8_t gas_limit[8] = {0};
  memcpy(gas_limit, data + offset, 8);
  offset += 8;

  uint8_t value[16];
  memcpy(value, data + offset, 16);
  offset += 16;

  // mock tx
  mol_builder_t b;
  MolBuilder_RawL2Transaction_init(&b);
  uint64_t chain_id = (uint64_t) CHAIN_ID;
  MolBuilder_RawL2Transaction_set_chain_id(&b, (uint8_t*)(&chain_id), 8);
  MolBuilder_RawL2Transaction_set_from_id(&b, (uint8_t*)(&from_id), 4);
  uint32_t nonce = 0;
  MolBuilder_RawL2Transaction_set_nonce(&b, (uint8_t*)(&nonce), 4);
  uint8_t prefix[7] = {0xFF, 0xFF, 0xFF, 'P', 'O', 'L', 'Y'};
  uint8_t args[4096];
  memcpy(args, prefix, 7); // prefix POLY
  args[7] = kind; // EVMC_CREATE
  uint32_t args_offset = 8;
  memcpy(args+args_offset, gas_limit, 8); // gas
  args_offset += 8;
  memcpy(args+args_offset, gas_price, 16); // gas_price
  args_offset += 16;
  memcpy(args+args_offset, value, 16); // value
  args_offset += 16;
  uint32_t data_size = (uint32_t)size;
  memcpy(args+args_offset, (uint8_t*)(&data_size), 4); // input data size
  args_offset += 4;
  memcpy(args+args_offset, data, size); //input data
  args_offset += size;

  if (native_transfer == 1) {
    memcpy(args+args_offset, transfer_to.bytes, 20); // native transfer to  
    args_offset += 20;
  }

  mol_seg_t bytes = build_Bytes(args, args_offset);
  MolBuilder_RawL2Transaction_set_args(&b, bytes.ptr, bytes.size);
  free(bytes.ptr);

  mol_seg_res_t res = MolBuilder_RawL2Transaction_build(b);
  if (MolReader_RawL2Transaction_verify(&res.seg, false) == MOL_OK) {
    gw_set_tx(res.seg.ptr, res.seg.size);
    int ret = run_polyjuice();
    debug_print_int("polyjuice ret:", ret);
    free(res.seg.ptr);
    return 0;
  }
  return -1; //not add to corpus
}
