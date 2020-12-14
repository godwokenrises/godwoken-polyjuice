/* pre-compiled Ethereum contracts */

uint64_t ecrecover_required_gas(uint8_t *input, size_t input_size) {
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
int ecrecover(uint8_t *input, size_t input_size,
              uint8_t *output, size_t *output_size) {
}
