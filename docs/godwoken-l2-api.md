
# Godwoken Layer 2 API
### Call Layer 2 contract

Load contract code (program) by syscalls then invoke the function.

```c
/**
 * Call layer 2 contract by its account id
 *
 * @param ctx       The godwoken context
 * @param to_id     The layer 2 contract's account id
 * @param args      The arguments data for the layer 2 contract
 * @param args_len  The arguments data length for the layer 2 contract
 * @param receipt   The receipt of current call to the layer 2 contract
 * @return          The status code, 0 is success
 */
int sys_call(void *ctx, uint32_t to_id, uint8_t *args, uint32_t args_len, gw_call_receipt_t *receipt);
```

### Syscalls
```c
/**
 * Load value by key from current contract account
 *
 * @param ctx    The godwoken context
 * @param key    The key (32 bytes)
 * @param value  The pointer to save the value of the key (32 bytes)
 * @return       The status code, 0 is success
 */
int sys_load(void *ctx, const uint8_t key[GW_KEY_BYTES], uint8_t value[GW_VALUE_BYTES]);

/**
 * Store key,value pair to current account's storage
 *
 * @param ctx    The godwoken context
 * @param key    The key
 * @param value  The value
 * @return       The status code, 0 is success
 */
int sys_store(void *ctx, const uint8_t key[GW_KEY_BYTES], const uint8_t value[GW_VALUE_BYTES]);

/**
 * Set the return data of current layer 2 contract (program) execution
 *
 * @param data   The data to return
 * @param len    The length of return data
 * @return       The status code, 0 is success
 */
int set_program_return_data(uint8_t *data, uint32_t len);

/**
 * Load call context (CallContext in godwoken.mol)
 *
 * @param addr   The pointer to save the `CallContext` data
 * @param len    The `CallContext` data length
 * @return       The status code, 0 is success
 */
int sys_load_call_context(void *addr, uint64_t *len);

/**
 * Load block information (BlockInfo in godwoken.mol)
 *
 * @param addr   The pointer to save the `BlockInfo` data
 * @param len    The `BlockInfo` data length
 * @return       The status code, 0 is success
 */
int sys_load_block_info(void *addr, uint64_t *len);

/**
 * Load layer 2 contract's code (program) as data by its account id
 *
 * @param addr   The pointer to save the program code data
 * @param len    The program code data length
 * @param offset The offset of the program code to load
 * @param id     The layer 2 contract's account id (see as contract address)
 * @return       The status code, 0 is success
 */
int sys_load_program_as_data(void *addr, uint64_t *len, size_t offset, uint64_t id);

/**
 * Load layer 2 contract's code (program) as executable riscv64 code by its account id
 *
 * @param addr           The pointer to save the program code data
 * @param memory_size    The memory size to save the program code
 * @param content_offset The offset of the program code to load
 * @param content_size   The size of the program code to load
 * @param id             The layer 2 contract's account id (see as contract address)
 * @return               The status code, 0 is success
 */
int sys_load_program_as_code(void *addr, uint64_t memory_size, uint64_t content_offset, uint64_t content_size, uint64_t id);

/**
 * Get account id by account address
 *
 * @param ctx        The godwoken context
 * @param address    The account address
 * @param account_id The pointer of the account id to save the result
 * @return           The status code, 0 is success
 */
int sys_get_account_id_by_address(gw_context_t *ctx, uint8_t[32] address, uint32_t * account_id);

/**
 * Get account address by account id
 *
 * @param ctx        The godwoken context
 * @param account_id The account id
 * @param address    The pointer of the account address to save the result
 * @return           The status code, 0 is success
 */
int sys_get_address_by_account_id(gw_context_t *ctx, uint32_t account_id, uint8_t[32] address);

/**
 * Get account's nonce
 *
 * @param ctx        The godwoken context
 * @param account_id The account id
 * @param nonce      The point of the nonce to save the result
 * @return           The status code, 0 is success
 */
int sys_get_account_nonce(gw_context_t *ctx, uint32_t account_id, uint32_t * nonce);

/**
 * Get layer 2 contract script (EVM contract code in polyjuice) by account id
 *
 * @param ctx        The godwoken context
 * @param account_id The account id
 * @param len        The length of the script
 * @param script     The pointer of the script to save the result
 * @return           The status code, 0 is success
 */
int sys_get_account_script(gw_context_t *ctx, uint32_t account_id, uint32_t * len, uint8_t * script);

/**
 * Get layer 2 block hash by number
 *
 * @param ctx        The godwoken context
 * @param block_hash The pointer of the layer 2 block hash to save the result
 * @param number     The number of the layer 2 block
 * @return           The status code, 0 is success
 */
int sys_get_block_hash(gw_context_t *ctx, uint8_t[32] block_hash, int64_t number);

/**
 * Emit a log (EVM LOG0, LOG1, LOGn in polyjuice)
 *
 * @param ctx            The godwoken context
 * @param data           The log data
 * @param data_length    The length of the log data
 * @return               The status code, 0 is success
 */
int sys_log(gw_context_t *ctx, const uint8_t *data, uint32_t data_length);
```

### Get Information (EVM terminology)

Static
```
The transaction gas price            ctx->call_context.args (given by sender)
The transaction origin account       ctx->call_context.args (encode into args)
The miner of the block               ctx->block_info.aggregator_id
The block number                     ctx->block_info.number
The block timestamp                  ctx->block_info.timestamp
The block gas limit                  [TODO] (given by aggregator in block_info or hard code)
The block difficulty                 [TODO] (given by aggregator in block_info or hard code)
The blockchain's ChainID             Hard code this value
```

Dynamic load
```
Check account existence              sys_get_account_id_by_address(address) => 0: exists, 1: not exists
Get storage                          sys_load(key)
Set storage                          sys_store(key, value)
Get balance                          sys_call(sudt_account_id, args, receipt)
Get code size (layer 2 contract)     sys_get_account_script(account_id) then get the length
Get code hash                        sys_get_account_script(account_id) then calculate the hash
Copy code                            sys_get_account_script(account_id) then copy a slice of the code
selfdestruct                         [TODO] need discuss
call                                 sys_call(vm_account_id, args, receipt)
Get block hash                       sys_get_block_hash(number)
Log                                  sys_log(data)
```
