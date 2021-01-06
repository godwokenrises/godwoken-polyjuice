#ifndef CONTRACTS_H_
#define CONTRACTS_H_

#include "sha256.h"
#include "ripemd160.h"

/* Protocol Params:
   [Referenced]: https://github.com/ethereum/go-ethereum/blob/master/params/protocol_params.go
*/
#define SHA256_BASE_GAS       60  // Base price for a SHA256 operation
#define SHA256_PERWORD_GAS    12  // Per-word price for a SHA256 operation
#define RIPEMD160_BASE_GAS    600 // Base price for a RIPEMD160 operation
#define RIPEMD160_PERWORD_GAS 120 // Per-word price for a RIPEMD160 operation
#define IDENTITY_BASE_GAS     15  // Base price for a data copy operation
#define IDENTITY_PERWORD_GAS  3   // Per-work price for a data copy operation

/* pre-compiled Ethereum contracts */

typedef uint64_t (*precompiled_contract_gas_fn)(const uint8_t *input_src, const size_t input_size);
typedef int (*precompiled_contract_fn)(gw_context_t *ctx,
                                       const uint8_t *input_src, const size_t input_size,
                                       uint8_t **output, size_t *output_size);

uint64_t ecrecover_required_gas(const uint8_t *input, const size_t input_size) {
  // Elliptic curve sender recovery gas price
  return 3000;
}

/*
  The input data: (hash, v, r, s), each 32 bytes
  ===============
    input[0 ..32]  => hash
    input[32..64]  => v (padded)
         [64]      => v
    input[64..128] => signature[0..64]
         [64..96 ] => r (u256)
         [96..128] => s (u256)
*/
int ecrecover(gw_context_t *ctx,
              const uint8_t *input_src,
              const size_t input_size,
              uint8_t **output, size_t *output_size) {

  int ret;
  secp256k1_context context;
  uint8_t secp_data[CKB_SECP256K1_DATA_SIZE];
#ifdef GW_GENERATOR
  ret = ckb_secp256k1_custom_verify_only_initialize(ctx, &context, secp_data);
#else
  ret = ckb_secp256k1_custom_verify_only_initialize(&context, secp_data);
#endif
  if (ret != 0) {
    return ret;
  }

  uint8_t input[128];
  memcpy(input, input_src, input_size);
  /* RightPadBytes */
  for (size_t i = input_size; i < 128; i++) {
    input[i] = 0;
  }
  for (int i = 32; i < 63; i ++) {
    if (input[i] != 0) {
      ckb_debug("input[32:63] not all zero!");
      return -1;
    }
  }
  /* FIXME: crypto.ValidateSignatureValues(v, r, s, false) */

  int recid = input[63] - 27;
  uint8_t signature_data[64];
  memcpy(signature_data, input + 64, 32);
  memcpy(signature_data + 32, input + 96, 32);
  secp256k1_ecdsa_recoverable_signature signature;
  if (secp256k1_ecdsa_recoverable_signature_parse_compact(&context, &signature, signature_data, recid) == 0) {
    ckb_debug("parse signature failed");
    return -1;
  }
  /* Recover pubkey */
  secp256k1_pubkey pubkey;
  if (secp256k1_ecdsa_recover(&context, &pubkey, &signature, input) != 1) {
    ckb_debug("recover public key failed");
    return -1;
  }

  /* Check pubkey hash */
  uint8_t temp[65];
  size_t pubkey_size = 33;
  if (secp256k1_ec_pubkey_serialize(&context, temp,
                                    &pubkey_size, &pubkey,
                                    SECP256K1_EC_COMPRESSED) != 1) {
    ckb_debug("public key serialize failed");
    return -1;
  }

  union ethash_hash256 hash_result = ethash::keccak256(temp + 1, 64);
  *output = (uint8_t *)malloc(32);
  if (*output == NULL) {
    return -1;
  }
  memset(output, 0, 12);
  memcpy(output + 12, hash_result.bytes + 12, 20);
  *output_size = 32;
  return 0;
}

uint64_t sha256hash_required_gas(const uint8_t *input, const size_t input_size) {
  return (uint64_t)(input_size + 31) / 32 * SHA256_PERWORD_GAS + SHA256_BASE_GAS;
}


int sha256hash(gw_context_t *ctx,
               const uint8_t *input_src,
               const size_t input_size,
               uint8_t **output, size_t *output_size) {
  *output = (uint8_t *)malloc(32);
  if (*output == NULL) {
    return -1;
  }
  *output_size = 32;
  SHA256_CTX hash_ctx;
  sha256_init(&hash_ctx);
  sha256_update(&hash_ctx, input_src, input_size);
  sha256_final(&hash_ctx, *output);
  return 0;
}


uint64_t ripemd160hash_required_gas(const uint8_t *input, const size_t input_size) {
  return (uint64_t)(input_size + 31) / 32 * RIPEMD160_PERWORD_GAS + RIPEMD160_BASE_GAS;
}


int ripemd160hash(gw_context_t *ctx,
               const uint8_t *input_src,
               const size_t input_size,
               uint8_t **output, size_t *output_size) {
  *output = (uint8_t *)malloc(20);
  if (*output == NULL) {
    return -1;
  }
  *output_size = 20;
  ripemd160(input_src, input_size, *output);
  return 0;
}

uint64_t data_copy_required_gas(const uint8_t *input, const size_t input_size) {
  return (uint64_t)(input_size + 31) / 32 * IDENTITY_PERWORD_GAS + IDENTITY_BASE_GAS;
}


int data_copy(gw_context_t *ctx,
                  const uint8_t *input_src,
                  const size_t input_size,
                  uint8_t **output, size_t *output_size) {
  *output = (uint8_t *)malloc(input_size);
  if (*output == NULL) {
    return -1;
  }
  *output_size = input_size;
  memcpy(*output, input_src, input_size);
  return 0;
}

bool match_precompiled_address(const evmc_address *destination,
                            precompiled_contract_gas_fn *contract_gas,
                            precompiled_contract_fn *contract) {
  for (int i = 0; i < 19; i++) {
    if (destination->bytes[i] != 0) {
      return false;
    }
  }

  switch (destination->bytes[19]) {
  case 1:
    *contract_gas = ecrecover_required_gas;
    *contract = ecrecover;
    break;
  case 2:
    *contract_gas = sha256hash_required_gas;
    *contract = sha256hash;
    break;
  case 3:
    *contract_gas = ripemd160hash_required_gas;
    *contract = ripemd160hash;
    break;
  case 4:
    *contract_gas = data_copy_required_gas;
    *contract = data_copy;
    break;
  default:
    *contract_gas = NULL;
    *contract = NULL;
    return false;
  }
  return true;
}

#endif
