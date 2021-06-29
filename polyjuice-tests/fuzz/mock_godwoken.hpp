#include <iostream>
#include <evmc/evmc.hpp>
#include <evmc/mocked_host.hpp>
#include <common.h>

using namespace std;
using namespace evmc;

class MockedGodwoken : public MockedHost {
public:
  std::unordered_map<uint32_t, bytes32> gw_account;
  unordered_map<bytes32, bytes32> state;
  unordered_map<bytes32, bytes> code_store;

  result call(const evmc_message& msg) noexcept override {
    auto result = MockedHost::call(msg);
    return result;
  }
};

struct fuzz_input {
  evmc_revision rev{};
  evmc_message msg{};
  bytes raw_tx;
  MockedGodwoken mock_gw;

  /// Creates invalid input.
  fuzz_input() noexcept { msg.gas = -1; }

  explicit operator bool() const noexcept { return msg.gas != -1; }
};
auto in = fuzz_input{};
MockedGodwoken* gw_host = &in.mock_gw;


// TODO
// mock_godwoken.set_storage(
//   bytes32({202, 21, 28, 70, 21, 107, 178, 94, 20, 217, 66, 198, 87, 129, 250, 203, 109, 201, 220, 50, 224, 74, 196, 60, 29, 131, 235, 115, 74, 147, 160, 21}),
//   bytes32({202, 21, 28, 70, 21, 107, 178, 94, 20, 217, 66, 198, 87, 129, 250, 203, 109, 201, 220, 50, 224, 74, 196, 60, 29, 131, 235, 115, 74, 147, 160, 21}),
//   bytes32({202, 21, 28, 70, 21, 107, 178, 94, 20, 217, 66, 198, 87, 129, 250, 203, 109, 201, 220, 50, 224, 74, 196, 60, 29, 131, 235, 115, 74, 147, 160, 21})
// );

inline ostream& operator<<(ostream& stream, const bytes32& b32) {
  stream << "H256[";
  for (size_t i = 0; i < 31; i++)
    stream << (uint16_t)b32.bytes[i] << ", ";
  return stream << (uint16_t)b32.bytes[31] << ']';
}
inline ostream& operator<<(ostream& stream, const bytes& bs) {
  for (auto &&i : bs){
    stream << (uint16_t)i << ' ';
  }
  return stream;
}

bytes32 u256_to_bytes32(const uint8_t u8[32]) {
  auto ret = bytes32{};
  memcpy(ret.bytes, u8, 32);
  return ret;
}

// void dbg_print_bytes32(bytes32& b32) {
//   dbg_print(<< b32);
// }

extern "C" int gw_store_data(const uint64_t len, uint8_t *data);
/* store code or script */
int gw_store_data(const uint64_t len, uint8_t *data) {
  uint8_t script_hash[32];
  blake2b_hash(script_hash, data, len);

  dbg_print("gw_store_data blake2b_hash: ");
  dbg_print_h256(script_hash);

  bytes bs((uint8_t*)data, len);
  // debug_print
  cout << "\tbytes: " << bs << endl;
  cout << "\tdata: ";
  for (size_t i = 0; i < len; i++) {
    cout << (uint16_t)*(data + i) << ' ';
  }
  in.mock_gw.code_store[u256_to_bytes32(script_hash)] = bs;
  return 0;
}

extern "C" int gw_sys_load_data(uint8_t* addr, uint64_t* len_ptr, uint64_t offset, uint8_t data_hash[32]) {
  auto search = in.mock_gw.code_store.find(u256_to_bytes32(data_hash));
  if (search == in.mock_gw.code_store.end()) {
    return GW_ERROR_NOT_FOUND;
  }
  *len_ptr = search->second.size();
  search->second.copy(addr, *len_ptr);
  return 0;
}

void print_state() {
  for (auto kv : gw_host->state) {
    cout << "\t key:\t" << kv.first << endl << "\t value:\t" << kv.second << endl;
  }
}

// sys_load from state
extern "C" int gw_sys_load(const uint8_t k[32], uint8_t v[32]) {
  auto search = gw_host->state.find(u256_to_bytes32(k));
  if (search == gw_host->state.end()) {
    dbg_print("gw_sys_load failed, missing key:");
    dbg_print_h256(k);
    dbg_print("all the state as following:");
    print_state();
    return GW_ERROR_NOT_FOUND;
  }
  memcpy(v, search->second.bytes, 32);
  return 0;
}

extern "C" void gw_update_raw(const uint8_t k[32], const uint8_t v[32]){
  in.mock_gw.state[u256_to_bytes32(k)] = u256_to_bytes32(v);

  // print_state();
}

extern "C" void gw_load_transaction_from_raw_tx(uint8_t* addr, uint64_t* len) {
  *len = in.raw_tx.size();
  in.raw_tx.copy(addr, *len);
}

extern "C" void gw_sys_set_return_data(uint8_t* addr, uint64_t len) {
  in.mock_gw.call_result = make_result(evmc_status_code{}, 0, addr, len);
}

extern "C" void gw_sys_get_block_hash(uint8_t block_hash[32], uint64_t number) {
  memcpy(block_hash, gw_host->get_block_hash(number).bytes, 32);
}

extern "C" int gw_sys_load_blockinfo(uint8_t* bi_addr, uint64_t* len_ptr) {
  /** 
   * TODO: block_info fuzzInput
   * struct BlockInfo {
   *  block_producer_id: Uint32,
   *  number: Uint64,
   *  timestamp: Uint64}
   */
  const uint8_t mock_new_block_info[] = {0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  *len_ptr = sizeof(mock_new_block_info);
  memcpy((uint8_t*)bi_addr, mock_new_block_info, *len_ptr);
  return 0;
}

extern "C" int gw_sys_load_script_hash_by_account_id(const uint32_t account_id, uint8_t script_hash[32]) {
  dbg_print("sys_get_script_hash_by_account_id account_id = %d", account_id);

  uint8_t key[32] = {0};
  gw_build_account_field_key(account_id, GW_ACCOUNT_SCRIPT_HASH, key);
  return gw_sys_load(key, script_hash);

  // FIXME read script_hash from mock State+CodeStore
  // static const uint8_t test_script_hash[6][32] = {
  //   {231, 196, 69, 164, 212, 229, 83, 6, 137, 240, 237, 105, 234, 223, 101, 133, 197, 66, 85, 214, 112, 85, 87, 71, 17, 170, 138, 126, 128, 173, 186, 76},
  //   {50, 15, 9, 23, 166, 82, 42, 69, 226, 148, 203, 184, 168, 8, 210, 62, 226, 187, 187, 21, 122, 141, 152, 55, 88, 230, 63, 204, 23, 3, 166, 102},
  //   {221, 60, 233, 16, 227, 19, 49, 118, 137, 43, 193, 160, 145, 21, 141, 6, 43, 206, 191, 210, 105, 160, 112, 23, 155, 184, 101, 113, 47, 247, 216, 122},
  //   {48, 160, 141, 250, 92, 214, 34, 124, 231, 78, 106, 179, 173, 80, 61, 55, 161, 156, 45, 114, 214, 222, 9, 77, 4, 104, 52, 44, 30, 149, 27, 36},
  //   {103, 167, 175, 25, 71, 242, 5, 31, 102, 236, 38, 188, 223, 212, 241, 99, 13, 4, 40, 150, 151, 55, 40, 147, 64, 29, 108, 50, 37, 159, 55, 137},
  //   {125, 181, 86, 185, 69, 172, 188, 175, 36, 25, 118, 119, 114, 72, 199, 183, 204, 25, 147, 120, 109, 220, 192, 171, 10, 235, 47, 230, 42, 210, 169, 223}};
}

extern "C" int gw_sys_get_script_hash_by_short_address(uint8_t *script_hash_addr,
                                                       uint8_t *prefix_addr,
                                                       uint64_t prefix_len) {
  for (auto pair : gw_host->code_store) {
    if (0 == memcmp(pair.first.bytes, prefix_addr, prefix_len)) {
      memcpy(script_hash_addr, pair.first.bytes, sizeof(pair.first.bytes));
      return 0;
    }
  }
  
  dbg_print("gw_sys_get_script_hash_by_short_address failed");
  return GW_ERROR_NOT_FOUND;
}

extern "C" int gw_sys_load_account_id_by_script_hash(uint8_t *script_hash,
                                                     uint32_t *account_id_ptr) {
  uint8_t raw_id_key[32];
  gw_build_script_hash_to_account_id_key(script_hash, raw_id_key);
  uint8_t result_addr[32];
  int ret = gw_sys_load(raw_id_key, result_addr);
  if (ret != 0) return ret;
  *account_id_ptr = *((uint32_t *)result_addr);
  return 0;
}

extern "C" int gw_sys_load_account_script(uint8_t *script_addr,
                                          uint64_t *len_ptr,
                                          const uint64_t offset,
                                          const uint32_t account_id) {
  uint8_t script_hash[32];
  int ret = gw_sys_load_script_hash_by_account_id(account_id, script_hash);
  if (ret != 0) {
    return ret;
  }
  return gw_sys_load_data(script_addr, len_ptr, offset, script_hash);

  // int ret = MOCK_SUCCESS;
  // static const uint8_t account1_scripts[] = {117, 0, 0, 0, 16, 0, 0, 0, 48, 0, 0, 0, 49, 0, 0, 0, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 1, 64, 0, 0, 0, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  // static const uint8_t account2_scripts[] = {89, 0, 0, 0, 16, 0, 0, 0, 48, 0, 0, 0, 49, 0, 0, 0, 5, 108, 171, 165, 10, 111, 194, 87, 79, 38, 74, 23, 199, 7, 250, 53, 120, 75, 230, 229, 154, 244, 114, 163, 65, 119, 108, 251, 137, 16, 190, 229, 1, 36, 0, 0, 0, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 1, 0, 0, 0};
  // static const uint8_t account4_scripts[] = {97, 0, 0, 0, 16, 0, 0, 0, 48, 0, 0, 0, 49, 0, 0, 0, 61, 131, 245, 41, 45, 5, 161, 161, 151, 161, 101, 38, 160, 60, 251, 86, 103, 65, 171, 189, 194, 72, 182, 31, 188, 159, 136, 253, 36, 110, 14, 98, 1, 44, 0, 0, 0, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 2, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0};
  // static const uint8_t account5_scripts[] = {109, 0, 0, 0, 16, 0, 0, 0, 48, 0, 0, 0, 49, 0, 0, 0, 5, 108, 171, 165, 10, 111, 194, 87, 79, 38, 74, 23, 199, 7, 250, 53, 120, 75, 230, 229, 154, 244, 114, 163, 65, 119, 108, 251, 137, 16, 190, 229, 1, 56, 0, 0, 0, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 169, 2, 0, 0, 0, 127, 206, 210, 20, 115, 27, 194, 169, 199, 79, 204, 192, 210, 154, 137, 78, 143, 170, 217, 240};
  // switch (account_id) {
  //   case 1:
  //     *len = sizeof(account1_scripts);
  //     memcpy(script, account1_scripts + offset, *len - offset);
  //     break;
  //   case 2:
  //     *len = sizeof(account2_scripts);
  //     memcpy(script, account2_scripts + offset, *len - offset);
  //     break;
  //   case 4:
  //     *len = sizeof(account4_scripts);
  //     memcpy(script, account4_scripts + offset, *len - offset);
  //     break;
  //   // case 5:
  //   //   *len = sizeof(account5_scripts);
  //   //   memcpy(script, account5_scripts + offset, *len - offset);
  //   //   break;
  //   default:
  //     ret = GW_ERROR_NOT_FOUND;
  // }
  // return ret;
}

extern "C" int gw_sys_load_rollup_config(uint8_t *addr,
                                         uint64_t *len_ptr) {
  // TODO: build RollupConfig, @see polyjuice-tests/src/helper.rs
  const uint8_t rollup_config[] = {189, 1, 0, 0, 60, 0, 0, 0, 92, 0, 0, 0, 124, 0, 0, 0, 156, 0, 0, 0, 188, 0, 0, 0, 220, 0, 0, 0, 252, 0, 0, 0, 28, 1, 0, 0, 60, 1, 0, 0, 68, 1, 0, 0, 76, 1, 0, 0, 84, 1, 0, 0, 85, 1, 0, 0, 89, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 161, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 162, 108, 221, 56, 188, 143, 219, 128, 88, 69, 24, 221, 22, 50, 19, 186, 0, 97, 224, 131, 145, 163, 114, 184, 192, 255, 122, 103, 171, 200, 106, 67, 222};
  *len_ptr = sizeof(rollup_config);
  memcpy(addr, rollup_config, *len_ptr);
  return 0;
}

int init() {
  // init block_hash
  gw_host->block_hash = bytes32({7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7});
  
  // init account nonce
  const uint8_t zero_nonce[32] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  
  const uint8_t account_4_key[32] = {4, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  const uint8_t poly_destructed_key[32] = {5, 0, 0, 0, 255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  
  gw_update_raw(account_4_key, zero_nonce);
  gw_update_raw(poly_destructed_key, zero_nonce);
  
  // in.mock_gw.gw_account[0] = bytes32({202, 21, 28, 70, 21, 107, 178, 94, 20, 217, 66, 198, 87, 129, 250, 203, 109, 201, 220, 50, 224, 74, 196, 60, 29, 131, 235, 115, 74, 147, 160, 21});

  // static uint8_t get_chain_id_tx[] = {92, 0, 0, 0, 20, 0, 0, 0, 24, 0, 0, 0, 28, 0, 0, 0, 32, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 56, 0, 0, 0, 255, 255, 255, 80, 79, 76, 89, 0, 8, 82, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 109, 76, 230, 60};
  // // version@20210625: {92, 0, 0, 0, 20, 0, 0, 0, 24, 0, 0, 0, 28, 0, 0, 0, 32, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 56, 0, 0, 0, 255, 255, 255, 80, 79, 76, 89, 0, 8, 82, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 109, 76, 230, 60};
  // *len = sizeof(get_chain_id_tx);
  // memcpy(addr, get_chain_id_tx, *len);

  // // create account and deploy getChainId contract
  // static uint8_t deploy_get_chain_id_contract[] = {73, 1, 0, 0, 20, 0, 0, 0, 24, 0, 0, 0, 28, 0, 0, 0, 32, 0, 0, 0, 4, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 37, 1, 0, 0, 255, 255, 255, 80, 79, 76, 89, 3, 240, 85, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 241, 0, 0, 0, 96, 128, 96, 64, 82, 52, 128, 21, 97, 0, 17, 87, 96, 0, 96, 0, 253, 91, 80, 97, 0, 23, 86, 91, 96, 204, 128, 97, 0, 37, 96, 0, 57, 96, 0, 243, 254, 96, 128, 96, 64, 82, 52, 128, 21, 96, 16, 87, 96, 0, 96, 0, 253, 91, 80, 96, 4, 54, 16, 96, 44, 87, 96, 0, 53, 96, 224, 28, 128, 99, 109, 76, 230, 60, 20, 96, 50, 87, 96, 44, 86, 91, 96, 0, 96, 0, 253, 91, 96, 56, 96, 76, 86, 91, 96, 64, 81, 96, 67, 145, 144, 96, 112, 86, 91, 96, 64, 81, 128, 145, 3, 144, 243, 91, 96, 0, 96, 0, 70, 144, 80, 128, 145, 80, 80, 96, 92, 86, 80, 91, 144, 86, 96, 149, 86, 91, 96, 105, 129, 96, 138, 86, 91, 130, 82, 91, 80, 80, 86, 91, 96, 0, 96, 32, 130, 1, 144, 80, 96, 131, 96, 0, 131, 1, 132, 96, 98, 86, 91, 91, 146, 145, 80, 80, 86, 91, 96, 0, 129, 144, 80, 91, 145, 144, 80, 86, 91, 254, 162, 100, 105, 112, 102, 115, 88, 34, 18, 32, 3, 36, 140, 112, 116, 35, 57, 185, 199, 86, 232, 210, 111, 220, 122, 33, 250, 178, 163, 13, 127, 44, 169, 160, 247, 149, 71, 178, 184, 168, 61, 64, 100, 115, 111, 108, 99, 67, 0, 8, 2, 0, 51};
  // // version@20210625: {73, 1, 0, 0, 20, 0, 0, 0, 24, 0, 0, 0, 28, 0, 0, 0, 32, 0, 0, 0, 3, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 37, 1, 0, 0, 255, 255, 255, 80, 79, 76, 89, 3, 240, 85, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 241, 0, 0, 0, 96, 128, 96, 64, 82, 52, 128, 21, 97, 0, 17, 87, 96, 0, 96, 0, 253, 91, 80, 97, 0, 23, 86, 91, 96, 204, 128, 97, 0, 37, 96, 0, 57, 96, 0, 243, 254, 96, 128, 96, 64, 82, 52, 128, 21, 96, 16, 87, 96, 0, 96, 0, 253, 91, 80, 96, 4, 54, 16, 96, 44, 87, 96, 0, 53, 96, 224, 28, 128, 99, 109, 76, 230, 60, 20, 96, 50, 87, 96, 44, 86, 91, 96, 0, 96, 0, 253, 91, 96, 56, 96, 76, 86, 91, 96, 64, 81, 96, 67, 145, 144, 96, 112, 86, 91, 96, 64, 81, 128, 145, 3, 144, 243, 91, 96, 0, 96, 0, 70, 144, 80, 128, 145, 80, 80, 96, 92, 86, 80, 91, 144, 86, 96, 149, 86, 91, 96, 105, 129, 96, 138, 86, 91, 130, 82, 91, 80, 80, 86, 91, 96, 0, 96, 32, 130, 1, 144, 80, 96, 131, 96, 0, 131, 1, 132, 96, 98, 86, 91, 91, 146, 145, 80, 80, 86, 91, 96, 0, 129, 144, 80, 91, 145, 144, 80, 86, 91, 254, 162, 100, 105, 112, 102, 115, 88, 34, 18, 32, 3, 36, 140, 112, 116, 35, 57, 185, 199, 86, 232, 210, 111, 220, 122, 33, 250, 178, 163, 13, 127, 44, 169, 160, 247, 149, 71, 178, 184, 168, 61, 64, 100, 115, 111, 108, 99, 67, 0, 8, 2, 0, 51};
  // *len = sizeof(deploy_get_chain_id_contract);
  // memcpy(addr, deploy_get_chain_id_contract, *len);

  // TODO: construct mock godwoken context => gw_context_init in run_polyjuice()
  return 0;
}
