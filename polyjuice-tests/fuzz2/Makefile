OS = Unknown
ifneq ($(shell uname -a | grep -i Darwin),)
	OS = MacOS
endif
ifneq ($(shell uname -a | grep -i Linux),)
	OS = Linux
endif
ifeq ($(OS),Unknown)
	echo "error: unsupported OS"; exit 1
endif

NPROC?=4
CXX=clang++
CC=clang
LLVM_PROFDATA=llvm-profdata
LLVM_COV=llvm-cov

DEPS := ../../deps
BUILD := build

SECP_DIR := $(DEPS)/secp256k1-fix
SECP256K1_SRC := $(SECP_DIR)/src/ecmult_static_pre_context.h

CFLAGS_SECP := -isystem $(SECP_DIR)/src -isystem $(SECP_DIR)
CFLAGS_CKB_STD = -I./ -I$(DEPS)/ckb-c-stdlib -I$(DEPS)/ckb-c-stdlib/molecule -Wno-incompatible-pointer-types
CFLAGS_ETHASH := -I$(DEPS)/ethash/include -I$(DEPS)/ethash/lib/ethash -I$(DEPS)/ethash/lib/keccak -I$(DEPS)/ethash/lib/support
CFLAGS_EVMONE := -I$(DEPS)/evmone/lib/evmone -I$(DEPS)/evmone/include -I$(DEPS)/evmone/evmc/include -I$(DEPS)/evmone/evmc/tools/
CFLAGS_SMT := -I$(DEPS)/godwoken-scripts/c/deps/sparse-merkle-tree/c
CFLAGS_GODWOKEN := -I$(DEPS)/godwoken-scripts/c
CFLAGS_MBEDTLS := -I$(DEPS)/mbedtls/include
CFLAGS_CRYPTO_ALGORITHMS := -I$(DEPS)/crypto-algorithms
CFLAGS_INTX := -I$(DEPS)/intx/lib/intx -I$(DEPS)/intx/include
CFLAGS_BN128 := -I$(DEPS)/bn128/include
CFLAGS_GW_SIM := -I$(DEPS)/gw-syscall-simulator/include
CFLAGS := -Wall -O2 -I../../c -I../../c/ripemd160 $(CFLAGS_CKB_STD) $(CFLAGS_ETHASH) $(CFLAGS_EVMONE) $(CFLAGS_SMT) $(CFLAGS_GODWOKEN) $(CFLAGS_SECP) $(CFLAGS_MBEDTLS) $(CFLAGS_CRYPTO_ALGORITHMS) $(CFLAGS_INTX) $(CFLAGS_BN128) $(CFLAGS_GW_SIM)
CXXFLAGS := $(CFLAGS) -std=c++1z 
LDFLAGS := -Wl,--gc-sections,-rpath,$(DEPS)/gw-syscall-simulator/target/debug
SANITIZER_FLAGS := -g -O1 -fsanitize=fuzzer,address,undefined -Wno-incompatible-pointer-types
LIMIT_ERROR := -ferror-limit=10

# TODO: read PROTOCOL_VERSION from deps/godwoken-scripts/c/Makefile
MOLC := moleculec
MOLC_VERSION := $(shell cat $(DEPS)/godwoken-scripts/c/Makefile | egrep "MOLC_VERSION :=" | awk '{print $$3}')
PROTOCOL_VERSION := $(shell cat $(DEPS)/godwoken-scripts/c/Makefile | egrep "PROTOCOL_VERSION :=" | awk '{print $$3}')
PROTOCOL_SCHEMA_URL := https://raw.githubusercontent.com/nervosnetwork/godwoken/${PROTOCOL_VERSION}/crates/types/schemas

ALL_OBJS := $(BUILD)/keccak.o $(BUILD)/keccakf800.o \
  $(BUILD)/execution_state.o $(BUILD)/evmc_hex.o $(BUILD)/baseline.o $(BUILD)/analysis.o $(BUILD)/instruction_metrics.o $(BUILD)/instruction_names.o $(BUILD)/execution.o $(BUILD)/instructions.o $(BUILD)/instructions_calls.o $(BUILD)/evmone.o \
  $(BUILD)/sha256.o $(BUILD)/memzero.o $(BUILD)/ripemd160.o $(BUILD)/bignum.o $(BUILD)/platform_util.o
BIN_DEPS := ../../c/contracts.h ../../c/sudt_contracts.h ../../c/other_contracts.h ../../c/polyjuice.h ../../c/polyjuice_utils.h $(BUILD)/secp256k1_data_info.h $(ALL_OBJS)
GENERATOR_DEPS := ../../c/generator/secp256k1_helper.h $(BIN_DEPS)
VALIDATOR_DEPS := ../../c/validator/secp256k1_helper.h $(BIN_DEPS)

CORPUS_DIR=corpus
COVERAGE_DIR=coverage
# TODO:
COVERAGE_FLAGS=-fprofile-instr-generate -fcoverage-mapping -I ../../c 
ifeq ($(OS),MacOS)
	COVERAGE_FLAGS+=-Wl,-U,_LLVMFuzzerCustomMutator -Wl,-U,_LLVMFuzzerInitialize
endif

EXTERNAL_HEADERS := $(DEPS)/ckb-c-stdlib-simulator/ckb_consts.hckb-c-stdlib-simulator-only

build-gw-syscall-simulator:
	cd $(DEPS)/gw-syscall-simulator/ && cargo build # Who doesn't like fast build?

build/fuzzer: generate-protocol $(GENERATOR_DEPS) build-gw-syscall-simulator
	$(CXX) $(CFLAGS) $(LDFLAGS) $(SANITIZER_FLAGS) $(LIMIT_ERROR) -L $(DEPS)/gw-syscall-simulator/target/debug -l gw_syscall_simluator -Ibuild -o $@ polyjuice_fuzzer.cc $(ALL_OBJS) 
build/fuzzer_log: generate-protocol $(GENERATOR_DEPS) build-gw-syscall-simulator
	$(CXX) $(CFLAGS) $(LDFLAGS) $(SANITIZER_FLAGS) $(LIMIT_ERROR) -L $(DEPS)/gw-syscall-simulator/target/debug -l gw_syscall_simluator -Ibuild -o $@ polyjuice_fuzzer.cc $(ALL_OBJS) -DPOLYJUICE_DEBUG_LOG

clean:
	rm -rf $(BUILD)/*

generate-protocol: check-moleculec-version build/blockchain.h build/godwoken.h
check-moleculec-version:
	test "$$(${MOLC} --version | awk '{ print $$2 }' | tr -d ' ')" = ${MOLC_VERSION}

build/blockchain.h: build/blockchain.mol
	${MOLC} --language c --schema-file $< > $@
build/godwoken.h: build/godwoken.mol
	${MOLC} --language c --schema-file $< > $@
build/blockchain.mol:
	mkdir -p build
	curl -L -o $@ ${PROTOCOL_SCHEMA_URL}/blockchain.mol
build/godwoken.mol:
	mkdir -p build
	curl -L -o $@ ${PROTOCOL_SCHEMA_URL}/godwoken.mol

