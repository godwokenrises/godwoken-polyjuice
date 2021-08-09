# TARGET := riscv64-unknown-linux-gnu
TARGET := riscv64-unknown-elf
CC := $(TARGET)-gcc
CXX := $(TARGET)-g++
LD := $(TARGET)-gcc
OBJCOPY := $(TARGET)-objcopy

SECP_DIR := deps/secp256k1-fix
CFLAGS_CKB_STD = -Ideps/ckb-c-stdlib -Ideps/ckb-c-stdlib/molecule
# CFLAGS_CBMT := -isystem deps/merkle-tree
CFLAGS_SECP := -isystem $(SECP_DIR)/src -isystem $(SECP_DIR)
CFLAGS_INTX := -Ideps/intx/lib/intx -Ideps/intx/include
CFLAGS_BN128 := -Ideps/bn128/include
CFLAGS_ETHASH := -Ideps/ethash/include -Ideps/ethash/lib/ethash -Ideps/ethash/lib/keccak -Ideps/ethash/lib/support
CFLAGS_CRYPTO_ALGORITHMS := -Ideps/crypto-algorithms
CFLAGS_MBEDTLS := -Ideps/mbedtls/include
CFLAGS_EVMONE := -Ideps/evmone/lib/evmone -Ideps/evmone/include -Ideps/evmone/evmc/include
CFLAGS_SMT := -Ideps/godwoken-scripts/c/deps/sparse-merkle-tree/c
CFLAGS_GODWOKEN := -Ideps/godwoken-scripts/c
CFLAGS := -O3 -Ic/ripemd160 $(CFLAGS_CKB_STD) $(CFLAGS_EVMONE) $(CFLAGS_INTX) $(CFLAGS_BN128) $(CFLAGS_ETHASH) $(CFLAGS_CRYPTO_ALGORITHMS) $(CFLAGS_MBEDTLS) $(CFLAGS_SMT) $(CFLAGS_GODWOKEN) $(CFLAGS_SECP)
CXXFLAGS := $(CFLAGS) -std=c++1z
# -Wl,<args> Pass the comma separated arguments in args to the linker(GNU linker)
LDFLAGS := -Wl,--gc-sections -Wall -fdata-sections -ffunction-sections

SECP256K1_SRC := $(SECP_DIR)/src/ecmult_static_pre_context.h

MOLC := moleculec
MOLC_VERSION := 0.6.1
PROTOCOL_VERSION := 2221efdfcf06351fa1884ea0f2df1604790c3378
PROTOCOL_SCHEMA_URL := https://raw.githubusercontent.com/nervosnetwork/godwoken/${PROTOCOL_VERSION}/crates/types/schemas

ALL_OBJS := build/evmone.o build/baseline.o build/analysis.o build/instruction_metrics.o build/instruction_names.o build/execution.o build/instructions.o build/instructions_calls.o \
  build/keccak.o build/keccakf800.o \
  build/sha256.o build/memzero.o build/ripemd160.o build/bignum.o build/platform_util.o
BIN_DEPS := c/contracts.h c/sudt_contracts.h c/other_contracts.h c/polyjuice.h c/polyjuice_utils.h build/secp256k1_data_info.h $(ALL_OBJS)
GENERATOR_DEPS := c/generator/secp256k1_helper.h $(BIN_DEPS)
VALIDATOR_DEPS := c/validator/secp256k1_helper.h $(BIN_DEPS)

BUILDER_DOCKER := nervos/ckb-riscv-gnu-toolchain:bionic-20190702-newlib-debug-symbols

all: build/test_contracts build/test_rlp build/generator build/validator build/generator_log build/validator_log build/test_ripemd160 build/blockchain.h build/godwoken.h

all-via-docker: generate-protocol
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make"

# Be aware that a given prerequisite will only be built once per invocation of make, at most.
all-in-debug-mode: LDFLAGS := -g
all-in-debug-mode: $(ALL_OBJS) build/generator_log build/validator_log

all-via-docker-in-debug-mode: generate-protocol
	docker run --rm -v `pwd`:/code -w /code ${BUILDER_DOCKER} make all-in-debug-mode

clean-via-docker:
	mkdir -p build
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make clean"

build/generator: c/generator.c $(GENERATOR_DEPS)
	cd $(SECP_DIR) && (git apply workaround-fix-g++-linking.patch || true) && cd - # apply patch
	$(CXX) $(CFLAGS) $(LDFLAGS) -Ibuild -o $@ c/generator.c $(ALL_OBJS) -DNO_DEBUG_LOG
	$(OBJCOPY) --only-keep-debug $@ $@.debug
	$(OBJCOPY) --strip-debug --strip-all $@
	cd $(SECP_DIR) && (git apply -R workaround-fix-g++-linking.patch || true) && cd - # revert patch

build/validator: c/validator.c $(VALIDATOR_DEPS)
	cd $(SECP_DIR) && (git apply workaround-fix-g++-linking.patch || true) && cd - # apply patch
	$(CXX) $(CFLAGS) $(LDFLAGS) -Ibuild -o $@ c/validator.c $(ALL_OBJS) -DNO_DEBUG_LOG
	$(OBJCOPY) --only-keep-debug $@ $@.debug
	$(OBJCOPY) --strip-debug --strip-all $@
	cd $(SECP_DIR) && (git apply -R workaround-fix-g++-linking.patch || true) && cd - # revert patch

build/generator_log: c/generator.c $(GENERATOR_DEPS)
	cd $(SECP_DIR) && (git apply workaround-fix-g++-linking.patch || true) && cd - # apply patch
	$(CXX) $(CFLAGS) $(LDFLAGS) -Ibuild -o $@ c/generator.c $(ALL_OBJS)
#	Don't separate the executable here, we need the whole one for performance analysis.
#	$(OBJCOPY) --only-keep-debug $@ $@.debug
#	$(OBJCOPY) --strip-debug --strip-all $@
	cd $(SECP_DIR) && (git apply -R workaround-fix-g++-linking.patch || true) && cd - # revert patch

build/validator_log: c/validator.c $(VALIDATOR_DEPS)
	cd $(SECP_DIR) && (git apply workaround-fix-g++-linking.patch || true) && cd - # apply patch
	$(CXX) $(CFLAGS) $(LDFLAGS) -Ibuild -o $@ c/validator.c $(ALL_OBJS)
#	Don't separate the executable here, we need the whole one for performance analysis.
#	$(OBJCOPY) --only-keep-debug $@ $@.debug
#	$(OBJCOPY) --strip-debug --strip-all $@
	cd $(SECP_DIR) && (git apply -R workaround-fix-g++-linking.patch || true) && cd - # revert patch

build/test_contracts: c/tests/test_contracts.c $(VALIDATOR_DEPS)
	cd $(SECP_DIR) && (git apply workaround-fix-g++-linking.patch || true) && cd - # apply patch
	$(CXX) $(CFLAGS) $(LDFLAGS) -Ibuild -o $@ c/tests/test_contracts.c $(ALL_OBJS)
	$(OBJCOPY) --only-keep-debug $@ $@.debug
	$(OBJCOPY) --strip-debug --strip-all $@
	cd $(SECP_DIR) && (git apply -R workaround-fix-g++-linking.patch || true) && cd - # revert patch

build/test_rlp: c/tests/test_rlp.c $(VALIDATOR_DEPS)
	cd $(SECP_DIR) && (git apply workaround-fix-g++-linking.patch || true) && cd - # apply patch
	$(CXX) $(CFLAGS) $(LDFLAGS) -Ibuild -o $@ c/tests/test_rlp.c $(ALL_OBJS)
	$(OBJCOPY) --only-keep-debug $@ $@.debug
	$(OBJCOPY) --strip-debug --strip-all $@
	cd $(SECP_DIR) && (git apply -R workaround-fix-g++-linking.patch || true) && cd - # revert patch

build/test_ripemd160: c/ripemd160/test_ripemd160.c c/ripemd160/ripemd160.h c/ripemd160/memzero.h $(ALL_OBJS)
	$(CXX) $(CFLAGS) $(LDFLAGS) -Ibuild -o $@ c/ripemd160/test_ripemd160.c $(ALL_OBJS)
	riscv64-unknown-elf-run build/test_ripemd160

build/evmone.o: deps/evmone/lib/evmone/evmone.cpp
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -c -o $@ $< -DPROJECT_VERSION=\"0.5.0-dev\"
build/baseline.o: deps/evmone/lib/evmone/baseline.cpp
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -c -o $@ $<
build/analysis.o: deps/evmone/lib/evmone/analysis.cpp
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -c -o $@ $<
build/execution.o: deps/evmone/lib/evmone/execution.cpp
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -c -o $@ $<
build/instructions.o: deps/evmone/lib/evmone/instructions.cpp
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -c -o $@ $<
build/instruction_metrics.o: deps/evmone/evmc/lib/instructions/instruction_metrics.c
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -c -o $@ $<
build/instruction_names.o: deps/evmone/evmc/lib/instructions/instruction_names.c
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -c -o $@ $<
build/instructions_calls.o: deps/evmone/lib/evmone/instructions_calls.cpp
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -c -o $@ $<

build/keccak.o: deps/ethash/lib/keccak/keccak.c build/keccakf800.o
	$(CC) $(CFLAGS) $(LDFLAGS) -c -o $@ $<
# build/keccakf1600.o: deps/ethash/lib/keccak/keccakf1600.c
# 	$(CC) $(CFLAGS) $(LDFLAGS) -c -o $@ $<
build/keccakf800.o: deps/ethash/lib/keccak/keccakf800.c
	$(CC) $(CFLAGS) $(LDFLAGS)  -c -o $@ $<

# build/div.o: deps/intx/lib/intx/div.cpp
# 	$(CXX) $(CFLAGS) $(LDFLAGS) -c -o $@ $<

build/memzero.o: c/ripemd160/memzero.c
	$(CXX) $(CFLAGS) $(LDFLAGS) -c -o $@ $<
build/ripemd160.o: c/ripemd160/ripemd160.c
	$(CXX) $(CFLAGS) $(LDFLAGS) -c -o $@ $<

build/platform_util.o: deps/mbedtls/library/platform_util.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c -o $@ $<
build/bignum.o: deps/mbedtls/library/bignum.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c -o $@ $<

build/sha256.o: deps/crypto-algorithms/sha256.c
	$(CXX) $(CFLAGS) $(LDFLAGS) -c -o $@ $<

build/secp256k1_data_info.h: build/dump_secp256k1_data
	$<
build/dump_secp256k1_data: c/dump_secp256k1_data.c $(SECP256K1_SRC)
	mkdir -p build
	gcc $(CFLAGS) -o $@ $<
$(SECP256K1_SRC):
	cd $(SECP_DIR) && \
    (git apply -R workaround-fix-g++-linking.patch || true) && \
		./autogen.sh && \
		CC=$(CC) LD=$(LD) ./configure --with-bignum=no --enable-ecmult-static-precomputation --enable-endomorphism --enable-module-recovery --host=$(TARGET) && \
    make src/ecmult_static_pre_context.h src/ecmult_static_context.h

generate-protocol: check-moleculec-version build/blockchain.h build/godwoken.h
check-moleculec-version:
	test "$$(${MOLC} --version | awk '{ print $$2 }' | tr -d ' ')" = ${MOLC_VERSION}

build/blockchain.mol:
	mkdir -p build
	curl -L -o $@ ${PROTOCOL_SCHEMA_URL}/blockchain.mol

build/godwoken.mol:
	mkdir -p build
	curl -L -o $@ ${PROTOCOL_SCHEMA_URL}/godwoken.mol

build/blockchain.h: build/blockchain.mol
	${MOLC} --language c --schema-file $< > $@

build/godwoken.h: build/godwoken.mol
	${MOLC} --language c --schema-file $< > $@

fmt:
	clang-format -i -style=Google c/**/*.*

clean:
	rm -rf build/*
	cd $(SECP_DIR) && [ -f "Makefile" ] && make distclean && make clean
	rm -rf $(SECP256K1_SRC)
