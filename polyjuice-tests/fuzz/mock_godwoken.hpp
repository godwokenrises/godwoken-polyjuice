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

void print_bytes32(bytes32& b32) {
  cout << b32;
}

extern "C" int init();
extern "C" int gw_update_raw(const uint8_t k[32], const uint8_t v[32]);

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

int gw_update_raw(const uint8_t k[32], const uint8_t v[32]) {
  cout << "\tgw_update_raw..." << endl;
  in.mock_gw.state[u256_to_bytes32(k)] = u256_to_bytes32(v);
  
  // for (auto kv : in.mock_gw.state) {
  //   cout << "\tkey:\t" << kv.first << endl << "\tvalue:\t" << kv.second << endl;
  // }

  return 0;
}

extern "C" void gw_load_transaction_from_raw_tx(uint8_t* addr, uint64_t* len) {
  *len = in.raw_tx.size();
  in.raw_tx.copy(addr, *len);
}

int init() {
  // in.mock_gw.gw_account[0] = bytes32({202, 21, 28, 70, 21, 107, 178, 94, 20, 217, 66, 198, 87, 129, 250, 203, 109, 201, 220, 50, 224, 74, 196, 60, 29, 131, 235, 115, 74, 147, 160, 21});

  // in.raw_tx = 

  // static uint8_t get_chain_id_tx[] = {92, 0, 0, 0, 20, 0, 0, 0, 24, 0, 0, 0, 28, 0, 0, 0, 32, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 56, 0, 0, 0, 255, 255, 255, 80, 79, 76, 89, 0, 8, 82, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 109, 76, 230, 60};
  // // version@20210625: {92, 0, 0, 0, 20, 0, 0, 0, 24, 0, 0, 0, 28, 0, 0, 0, 32, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 56, 0, 0, 0, 255, 255, 255, 80, 79, 76, 89, 0, 8, 82, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 109, 76, 230, 60};
  // *len = sizeof(get_chain_id_tx);
  // memcpy(addr, get_chain_id_tx, *len);

  // // create account and deploy getChainId contract
  // static uint8_t deploy_get_chain_id_contract[] = {73, 1, 0, 0, 20, 0, 0, 0, 24, 0, 0, 0, 28, 0, 0, 0, 32, 0, 0, 0, 4, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 37, 1, 0, 0, 255, 255, 255, 80, 79, 76, 89, 3, 240, 85, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 241, 0, 0, 0, 96, 128, 96, 64, 82, 52, 128, 21, 97, 0, 17, 87, 96, 0, 96, 0, 253, 91, 80, 97, 0, 23, 86, 91, 96, 204, 128, 97, 0, 37, 96, 0, 57, 96, 0, 243, 254, 96, 128, 96, 64, 82, 52, 128, 21, 96, 16, 87, 96, 0, 96, 0, 253, 91, 80, 96, 4, 54, 16, 96, 44, 87, 96, 0, 53, 96, 224, 28, 128, 99, 109, 76, 230, 60, 20, 96, 50, 87, 96, 44, 86, 91, 96, 0, 96, 0, 253, 91, 96, 56, 96, 76, 86, 91, 96, 64, 81, 96, 67, 145, 144, 96, 112, 86, 91, 96, 64, 81, 128, 145, 3, 144, 243, 91, 96, 0, 96, 0, 70, 144, 80, 128, 145, 80, 80, 96, 92, 86, 80, 91, 144, 86, 96, 149, 86, 91, 96, 105, 129, 96, 138, 86, 91, 130, 82, 91, 80, 80, 86, 91, 96, 0, 96, 32, 130, 1, 144, 80, 96, 131, 96, 0, 131, 1, 132, 96, 98, 86, 91, 91, 146, 145, 80, 80, 86, 91, 96, 0, 129, 144, 80, 91, 145, 144, 80, 86, 91, 254, 162, 100, 105, 112, 102, 115, 88, 34, 18, 32, 3, 36, 140, 112, 116, 35, 57, 185, 199, 86, 232, 210, 111, 220, 122, 33, 250, 178, 163, 13, 127, 44, 169, 160, 247, 149, 71, 178, 184, 168, 61, 64, 100, 115, 111, 108, 99, 67, 0, 8, 2, 0, 51};
  // // version@20210625: {73, 1, 0, 0, 20, 0, 0, 0, 24, 0, 0, 0, 28, 0, 0, 0, 32, 0, 0, 0, 3, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 37, 1, 0, 0, 255, 255, 255, 80, 79, 76, 89, 3, 240, 85, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 241, 0, 0, 0, 96, 128, 96, 64, 82, 52, 128, 21, 97, 0, 17, 87, 96, 0, 96, 0, 253, 91, 80, 97, 0, 23, 86, 91, 96, 204, 128, 97, 0, 37, 96, 0, 57, 96, 0, 243, 254, 96, 128, 96, 64, 82, 52, 128, 21, 96, 16, 87, 96, 0, 96, 0, 253, 91, 80, 96, 4, 54, 16, 96, 44, 87, 96, 0, 53, 96, 224, 28, 128, 99, 109, 76, 230, 60, 20, 96, 50, 87, 96, 44, 86, 91, 96, 0, 96, 0, 253, 91, 96, 56, 96, 76, 86, 91, 96, 64, 81, 96, 67, 145, 144, 96, 112, 86, 91, 96, 64, 81, 128, 145, 3, 144, 243, 91, 96, 0, 96, 0, 70, 144, 80, 128, 145, 80, 80, 96, 92, 86, 80, 91, 144, 86, 96, 149, 86, 91, 96, 105, 129, 96, 138, 86, 91, 130, 82, 91, 80, 80, 86, 91, 96, 0, 96, 32, 130, 1, 144, 80, 96, 131, 96, 0, 131, 1, 132, 96, 98, 86, 91, 91, 146, 145, 80, 80, 86, 91, 96, 0, 129, 144, 80, 91, 145, 144, 80, 86, 91, 254, 162, 100, 105, 112, 102, 115, 88, 34, 18, 32, 3, 36, 140, 112, 116, 35, 57, 185, 199, 86, 232, 210, 111, 220, 122, 33, 250, 178, 163, 13, 127, 44, 169, 160, 247, 149, 71, 178, 184, 168, 61, 64, 100, 115, 111, 108, 99, 67, 0, 8, 2, 0, 51};
  // *len = sizeof(deploy_get_chain_id_contract);
  // memcpy(addr, deploy_get_chain_id_contract, *len);

  return 0;
}
