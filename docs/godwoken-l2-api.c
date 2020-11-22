
// # Godwoken Layer 2 API
// ## Generator
// ### Call Layer 1 contract
/**
 * Call layer 1 contract by its
 */
int sys_call(void *ctx, uint32_t to_id, uint8_t *args, uint32_t args_len, gw_call_receipt_t *receipt) {}

// ### Syscalls
/**
 * Load value by key from current contract account
 *
 * @param ctx    The godwoken context
 * @param key    The key (32 bytes)
 * @param value  The arrty to save the value of the key (32 bytes)
 */
int sys_load(void *ctx, const uint8_t key[GW_KEY_BYTES], uint8_t value[GW_VALUE_BYTES]) {
int sys_store(void *ctx, const uint8_t key[GW_KEY_BYTES], const uint8_t value[GW_VALUE_BYTES])

int set_program_return_data(uint8_t *data, uint32_t len)
int sys_load_call_context(void *addr, uint64_t *len)
int sys_load_block_info(void *addr, uint64_t *len)
int sys_load_program_as_data(void *addr, uint64_t *len, size_t offset, uint64_t id)
int sys_load_program_as_code(void *addr, uint64_t memory_size, uint64_t content_offset, uint64_t content_size, uint64_t id)
int sys_find_account_id_by_address(gw_context_t * cxt, uint8_t[32] address, uint32_t * account_id);
int sys_find_address_by_account_id(gw_context_t * cxt, uint32_t account_id, uint8_t[32] address);
int sys_get_account_nonce(gw_context_t * cxt, uint32_t account_id, uint32_t * nonce);
int sys_get_account_script(gw_context_t * cxt, uint32_t account_id, uint32_t * len, uint8_t * script);

// ## Validator
