#include <stdint.h>
#include <stddef.h>

#define GW_GENERATOR
/**
 * Layer 2 contract generator
 * The generator supposed to be run off-chain.
 * generator dynamic linking with the layer2 contract code,
 * and provides layer2 syscalls.
 * 
 * A program should be able to generate a post state after run the generator,
 * and should be able to use the states to construct a transaction that satifies
 * the validator.
 */
#include "polyjuice.h"

#define ASSERT_EQ(A, B) assert_eq(A, B, #A, #B, __FILE__, __LINE__)

struct test_case {
  bytes raw_tx;
  bytes expected_result{};
};

static uint raw_tx_idx = 0;

bool execute_predefined_transactions() {
  static int ret = init();
  // TODO: ASSERT_EQ(0, ret)
  if (ret != 0) {
    dbg_print("failed to init()");
    __builtin_trap();
  }

  bool all_good = true;
  const test_case pre_defined_test_cases[] = {
      // built by RawL2Transaction builder
      {// create account and deploy getChainId contract
       bytes({73, 1, 0, 0, 20, 0, 0, 0, 24, 0, 0, 0, 28, 0, 0, 0, 32, 0, 0, 0, 4, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 37, 1, 0, 0, 255, 255, 255, 80, 79, 76, 89, 3, 240, 85, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 241, 0, 0, 0, 96, 128, 96, 64, 82, 52, 128, 21, 97, 0, 17, 87, 96, 0, 96, 0, 253, 91, 80, 97, 0, 23, 86, 91, 96, 204, 128, 97, 0, 37, 96, 0, 57, 96, 0, 243, 254, 96, 128, 96, 64, 82, 52, 128, 21, 96, 16, 87, 96, 0, 96, 0, 253, 91, 80, 96, 4, 54, 16, 96, 44, 87, 96, 0, 53, 96, 224, 28, 128, 99, 109, 76, 230, 60, 20, 96, 50, 87, 96, 44, 86, 91, 96, 0, 96, 0, 253, 91, 96, 56, 96, 76, 86, 91, 96, 64, 81, 96, 67, 145, 144, 96, 112, 86, 91, 96, 64, 81, 128, 145, 3, 144, 243, 91, 96, 0, 96, 0, 70, 144, 80, 128, 145, 80, 80, 96, 92, 86, 80, 91, 144, 86, 96, 149, 86, 91, 96, 105, 129, 96, 138, 86, 91, 130, 82, 91, 80, 80, 86, 91, 96, 0, 96, 32, 130, 1, 144, 80, 96, 131, 96, 0, 131, 1, 132, 96, 98, 86, 91, 91, 146, 145, 80, 80, 86, 91, 96, 0, 129, 144, 80, 91, 145, 144, 80, 86, 91, 254, 162, 100, 105, 112, 102, 115, 88, 34, 18, 32, 3, 36, 140, 112, 116, 35, 57, 185, 199, 86, 232, 210, 111, 220, 122, 33, 250, 178, 163, 13, 127, 44, 169, 160, 247, 149, 71, 178, 184, 168, 61, 64, 100, 115, 111, 108, 99, 67, 0, 8, 2, 0, 51}),
       bytes{}},
      {// call getChainId contract
       bytes({92, 0, 0, 0, 20, 0, 0, 0, 24, 0, 0, 0, 28, 0, 0, 0, 32, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 56, 0, 0, 0, 255, 255, 255, 80, 79, 76, 89, 0, 8, 82, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 109, 76, 230, 60}),
       bytes({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})},

      /* simple_storage test case */
      // {bytes({89, 1, 0, 0, 20, 0, 0, 0, 24, 0, 0, 0, 28, 0, 0, 0, 32, 0, 0, 0, 4, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 53, 1, 0, 0, 255, 255, 255, 80, 79, 76, 89, 3, 240, 85, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 96, 128, 96, 64, 82, 91, 96, 123, 96, 0, 96, 0, 80, 129, 144, 144, 144, 85, 80, 91, 97, 0, 24, 86, 91, 96, 219, 128, 97, 0, 38, 96, 0, 57, 96, 0, 243, 254, 96, 128, 96, 64, 82, 96, 4, 54, 16, 96, 41, 87, 96, 0, 53, 96, 224, 28, 128, 99, 96, 254, 71, 177, 20, 96, 47, 87, 128, 99, 109, 76, 230, 60, 20, 96, 91, 87, 96, 41, 86, 91, 96, 0, 96, 0, 253, 91, 96, 89, 96, 4, 128, 54, 3, 96, 32, 129, 16, 21, 96, 68, 87, 96, 0, 96, 0, 253, 91, 129, 1, 144, 128, 128, 53, 144, 96, 32, 1, 144, 146, 145, 144, 80, 80, 80, 96, 132, 86, 91, 0, 91, 52, 128, 21, 96, 103, 87, 96, 0, 96, 0, 253, 91, 80, 96, 110, 96, 148, 86, 91, 96, 64, 81, 128, 130, 129, 82, 96, 32, 1, 145, 80, 80, 96, 64, 81, 128, 145, 3, 144, 243, 91, 128, 96, 0, 96, 0, 80, 129, 144, 144, 144, 85, 80, 91, 80, 86, 91, 96, 0, 96, 0, 96, 0, 80, 84, 144, 80, 96, 162, 86, 91, 144, 86, 254, 162, 100, 105, 112, 102, 115, 88, 34, 18, 32, 4, 77, 175, 78, 52, 173, 255, 198, 28, 59, 185, 232, 244, 0, 97, 115, 25, 114, 211, 45, 181, 184, 194, 188, 151, 81, 35, 218, 158, 152, 140, 62, 100, 115, 111, 108, 99, 67, 0, 6, 6, 0, 51}),
      //  bytes({})},

      // {bytes({124, 0, 0, 0, 20, 0, 0, 0, 24, 0, 0, 0, 28, 0, 0, 0, 32, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 88, 0, 0, 0, 255, 255, 255, 80, 79, 76, 89, 0, 8, 82, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 36, 0, 0, 0, 96, 254, 71, 177, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13, 16}),
      //  bytes({})},

      // {bytes({}),
      //  bytes({})},

      //  {bytes({}),
      //  bytes({})},
      // {// deploy BlockInfo contract
      //  bytes({107, 4, 0, 0, 20, 0, 0, 0, 24, 0, 0, 0, 28, 0, 0, 0, 32, 0, 0, 0, 4, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 71, 4, 0, 0, 255, 255, 255, 80, 79, 76, 89, 3, 0, 113, 2, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 19, 4, 0, 0, 96, 128, 96, 64, 82, 91, 96, 0, 64, 96, 0, 96, 0, 80, 129, 144, 144, 96, 0, 25, 22, 144, 85, 80, 68, 96, 1, 96, 0, 80, 129, 144, 144, 144, 85, 80, 69, 96, 2, 96, 0, 80, 129, 144, 144, 144, 85, 80, 67, 96, 3, 96, 0, 80, 129, 144, 144, 144, 85, 80, 66, 96, 4, 96, 0, 80, 129, 144, 144, 144, 85, 80, 65, 96, 5, 96, 0, 97, 1, 0, 10, 129, 84, 129, 115, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 2, 25, 22, 144, 131, 115, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 22, 2, 23, 144, 85, 80, 115, 161, 173, 34, 122, 211, 105, 245, 147, 181, 243, 208, 204, 147, 74, 104, 26, 80, 129, 28, 178, 115, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 22, 96, 5, 96, 0, 144, 84, 144, 97, 1, 0, 10, 144, 4, 115, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 22, 115, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 22, 20, 21, 21, 97, 0, 249, 87, 96, 0, 96, 0, 253, 91, 127, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 96, 0, 27, 96, 0, 96, 0, 80, 84, 96, 0, 25, 22, 20, 21, 21, 97, 1, 52, 87, 96, 0, 96, 0, 253, 91, 98, 190, 188, 32, 96, 2, 96, 0, 80, 84, 20, 21, 21, 97, 1, 75, 87, 96, 0, 96, 0, 253, 91, 91, 97, 1, 81, 86, 91, 97, 2, 179, 128, 97, 1, 96, 96, 0, 57, 96, 0, 243, 254, 96, 128, 96, 64, 82, 52, 128, 21, 97, 0, 17, 87, 96, 0, 96, 0, 253, 91, 80, 96, 4, 54, 16, 97, 0, 103, 87, 96, 0, 53, 96, 224, 28, 128, 99, 24, 142, 195, 86, 20, 97, 0, 109, 87, 128, 99, 26, 147, 209, 195, 20, 97, 0, 139, 87, 128, 99, 182, 186, 255, 227, 20, 97, 0, 169, 87, 128, 99, 209, 168, 42, 157, 20, 97, 0, 199, 87, 128, 99, 242, 201, 236, 216, 20, 97, 0, 229, 87, 128, 99, 246, 201, 147, 136, 20, 97, 1, 3, 87, 97, 0, 103, 86, 91, 96, 0, 96, 0, 253, 91, 97, 0, 117, 97, 1, 33, 86, 91, 96, 64, 81, 97, 0, 130, 145, 144, 97, 2, 22, 86, 91, 96, 64, 81, 128, 145, 3, 144, 243, 91, 97, 0, 147, 97, 1, 51, 86, 91, 96, 64, 81, 97, 0, 160, 145, 144, 97, 2, 22, 86, 91, 96, 64, 81, 128, 145, 3, 144, 243, 91, 97, 0, 177, 97, 1, 69, 86, 91, 96, 64, 81, 97, 0, 190, 145, 144, 97, 2, 22, 86, 91, 96, 64, 81, 128, 145, 3, 144, 243, 91, 97, 0, 207, 97, 1, 87, 86, 91, 96, 64, 81, 97, 0, 220, 145, 144, 97, 1, 222, 86, 91, 96, 64, 81, 128, 145, 3, 144, 243, 91, 97, 0, 237, 97, 1, 134, 86, 91, 96, 64, 81, 97, 0, 250, 145, 144, 97, 2, 22, 86, 91, 96, 64, 81, 128, 145, 3, 144, 243, 91, 97, 1, 11, 97, 1, 152, 86, 91, 96, 64, 81, 97, 1, 24, 145, 144, 97, 1, 250, 86, 91, 96, 64, 81, 128, 145, 3, 144, 243, 91, 96, 0, 96, 4, 96, 0, 80, 84, 144, 80, 97, 1, 48, 86, 91, 144, 86, 91, 96, 0, 96, 2, 96, 0, 80, 84, 144, 80, 97, 1, 66, 86, 91, 144, 86, 91, 96, 0, 96, 1, 96, 0, 80, 84, 144, 80, 97, 1, 84, 86, 91, 144, 86, 91, 96, 0, 96, 5, 96, 0, 144, 84, 144, 97, 1, 0, 10, 144, 4, 115, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 22, 144, 80, 97, 1, 131, 86, 91, 144, 86, 91, 96, 0, 96, 3, 96, 0, 80, 84, 144, 80, 97, 1, 149, 86, 91, 144, 86, 91, 96, 0, 96, 0, 96, 0, 80, 84, 144, 80, 97, 1, 167, 86, 91, 144, 86, 97, 2, 124, 86, 91, 97, 1, 183, 129, 97, 2, 50, 86, 91, 130, 82, 91, 80, 80, 86, 91, 97, 1, 199, 129, 97, 2, 69, 86, 91, 130, 82, 91, 80, 80, 86, 91, 97, 1, 215, 129, 97, 2, 113, 86, 91, 130, 82, 91, 80, 80, 86, 91, 96, 0, 96, 32, 130, 1, 144, 80, 97, 1, 243, 96, 0, 131, 1, 132, 97, 1, 174, 86, 91, 91, 146, 145, 80, 80, 86, 91, 96, 0, 96, 32, 130, 1, 144, 80, 97, 2, 15, 96, 0, 131, 1, 132, 97, 1, 190, 86, 91, 91, 146, 145, 80, 80, 86, 91, 96, 0, 96, 32, 130, 1, 144, 80, 97, 2, 43, 96, 0, 131, 1, 132, 97, 1, 206, 86, 91, 91, 146, 145, 80, 80, 86, 91, 96, 0, 97, 2, 61, 130, 97, 2, 80, 86, 91, 144, 80, 91, 145, 144, 80, 86, 91, 96, 0, 129, 144, 80, 91, 145, 144, 80, 86, 91, 96, 0, 115, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 130, 22, 144, 80, 91, 145, 144, 80, 86, 91, 96, 0, 129, 144, 80, 91, 145, 144, 80, 86, 91, 254, 162, 100, 105, 112, 102, 115, 88, 34, 18, 32, 113, 236, 22, 117, 175, 248, 197, 236, 108, 166, 237, 165, 131, 213, 225, 213, 35, 139, 217, 89, 232, 176, 199, 158, 172, 177, 24, 183, 62, 194, 199, 114, 100, 115, 111, 108, 99, 67, 0, 8, 2, 0, 51}),
      //  bytes({})},



      // {// getGenesisHash()                     fn_sighash: f6c99388
      //  bytes({92, 0, 0, 0, 20, 0, 0, 0, 24, 0, 0, 0, 28, 0, 0, 0, 32, 0, 0, 0, 4, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 56, 0, 0, 0, 255, 255, 255, 80, 79, 76, 89, 0, 8, 82, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 246, 201, 147, 136}),
      //  from_hex("0707070707070707070707070707070707070707070707070707070707070707")},

      // // getDifficulty() => 2500000000000000, fn_sighash: b6baffe3
      // bytes({92, 0, 0, 0, 20, 0, 0, 0, 24, 0, 0, 0, 28, 0, 0, 0, 32, 0, 0, 0, 4, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 56, 0, 0, 0, 255, 255, 255, 80, 79, 76, 89, 0, 8, 82, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 182, 186, 255, 227}),
      // from_hex(""),

      //   // getGasLimit()                        fn_sighash: 1a93d1c3
      //   bytes({92, 0, 0, 0, 20, 0, 0, 0, 24, 0, 0, 0, 28, 0, 0, 0, 32, 0, 0, 0, 4, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 56, 0, 0, 0, 255, 255, 255, 80, 79, 76, 89, 0, 8, 82, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 26, 147, 209, 195}),
      //   // getNumber()                          fn_sighash: f2c9ecd8
      //   bytes({92, 0, 0, 0, 20, 0, 0, 0, 24, 0, 0, 0, 28, 0, 0, 0, 32, 0, 0, 0, 4, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 56, 0, 0, 0, 255, 255, 255, 80, 79, 76, 89, 0, 8, 82, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 242, 201, 236, 216}),
      //   // getTimestamp()                       fn_sighash: 188ec356
      //   bytes({92, 0, 0, 0, 20, 0, 0, 0, 24, 0, 0, 0, 28, 0, 0, 0, 32, 0, 0, 0, 4, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 56, 0, 0, 0, 255, 255, 255, 80, 79, 76, 89, 0, 8, 82, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 24, 142, 195, 86}),
      //   // getCoinbase()                        fn_sighash: d1a82a9d
      //   bytes({92, 0, 0, 0, 20, 0, 0, 0, 24, 0, 0, 0, 28, 0, 0, 0, 32, 0, 0, 0, 4, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 56, 0, 0, 0, 255, 255, 255, 80, 79, 76, 89, 0, 8, 82, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 209, 168, 42, 157})
      // 000000000000000000000000a1ad227ad369f593b5f3d0cc934a681a50811cb2

  };

  for (auto &&tc : pre_defined_test_cases) {
    in.raw_tx = tc.raw_tx; // load_l2_transaction from pre_defined_test_cases
    
    ret = run_polyjuice();
    if (ret != 0) {
      dbg_print("run_polyjuice failed, result_code: %d", ret);
      all_good = false;
      // __builtin_trap();
    }
    //TODO: print RunResult as evmc_result and assert the result is expected
    if (tc.expected_result.size() > 0) {

      // TODO:
      // ASSERT_EQ(bytes_view(tc.expected_result,)

      // )
    }
    dbg_print("====================== run polyjuice finished %d times ======================", ++raw_tx_idx);
  }
  return all_good;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static bool predefined_test_passed = execute_predefined_transactions();
  if (!predefined_test_passed) {
    dbg_print("warn: execute_predefined_transactions failed");
    __builtin_trap();
  }

  // TODO: load RawL2Transaction from corpus
  // TODO: msg = pupulate_input(data, size), and fill the msg into LOAD_TRANSACTION SYSCALL
  in.raw_tx = bytes(data, size);

  //TODO: wrap run_polyjuice and return the RunResult => struct evmc_result call
  // const auto res = polyjuice_execute();
  run_polyjuice();
  dbg_print("====================== run polyjuice finished %d times ======================", ++raw_tx_idx);

  //TODO: check the RunResult

  // temp code
  if (size >= 0)
    __builtin_trap();

  return 0;
}
