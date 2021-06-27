#include <iostream>
#include <evmc/evmc.hpp>
#include <evmc/mocked_host.hpp>

using namespace std;
using namespace evmc;

class MockedGodwoken : public MockedHost {
public:
  std::unordered_map<uint32_t, bytes32> gw_account;
  unordered_map<bytes32, bytes32> state;

  result call(const evmc_message& msg) noexcept override {
    auto result = MockedHost::call(msg);
    return result;
  }
};

struct fuzz_input {
  evmc_revision rev{};
  evmc_message msg{};
  MockedGodwoken mock_gw;

  /// Creates invalid input.
  fuzz_input() noexcept { msg.gas = -1; }

  explicit operator bool() const noexcept { return msg.gas != -1; }
};

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

bytes32 uint256_to_bytes32(const uint8_t u8[32]) {
  auto ret = bytes32{};
  memcpy(ret.bytes, u8, 32);
  return ret;
}

void print_bytes32(bytes32& b32) {
  cout << b32;
}

extern "C" int init();
extern "C" int gw_update_raw(const uint8_t k[32], const uint8_t v[32]);

auto in = fuzz_input{};
int gw_update_raw(const uint8_t k[32], const uint8_t v[32]) {
  cout << "\tgw_update_raw..." << endl;
  in.mock_gw.state[uint256_to_bytes32(k)] = uint256_to_bytes32(v);
  
  for (auto kv : in.mock_gw.state) {
    cout << "\tkey:\t" << kv.first << endl << "\tvalue:\t" << kv.second << endl;
  }

  return 0;
}

int init() {
  // in.mock_gw.gw_account[0] = bytes32({202, 21, 28, 70, 21, 107, 178, 94, 20, 217, 66, 198, 87, 129, 250, 203, 109, 201, 220, 50, 224, 74, 196, 60, 29, 131, 235, 115, 74, 147, 160, 21});

  return 0;
}
