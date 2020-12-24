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
CFLAGS_ETHASH := -Ideps/ethash/include -Ideps/ethash/lib/ethash -Ideps/ethash/lib/keccak -Ideps/ethash/lib/support
CFLAGS_EVMONE := -Ideps/evmone/lib/evmone -Ideps/evmone/include -Ideps/evmone/evmc/include
CFLAGS_GODWOKEN := -Ideps/godwoken-fix/c
CFLAGS := -O3  $(CFLAGS_CKB_STD) $(CFLAGS_EVMONE) $(CFLAGS_INTX) $(CFLAGS_ETHASH) $(CFLAGS_GODWOKEN) $(CFLAGS_SECP) -Wall -g
CXXFLAGS := $(CFLAGS) -std=c++1z
LDFLAGS := -fdata-sections -ffunction-sections -Wl,--gc-sections

SECP256K1_SRC := $(SECP_DIR)/src/ecmult_static_pre_context.h

MOLC := moleculec
MOLC_VERSION := 0.6.1
PROTOCOL_SCHEMA_DIR := ./deps/godwoken-fix/crates/types/schemas

ALL_OBJS := build/evmone.o build/analysis.o build/execution.o build/instructions.o build/instructions_calls.o build/div.o build/keccak.o build/keccakf800.o build/keccakf1600.o

# docker pull nervos/ckb-riscv-gnu-toolchain:gnu-bionic-20191012
# BUILDER_DOCKER := nervos/ckb-riscv-gnu-toolchain@sha256:aae8a3f79705f67d505d1f1d5ddc694a4fd537ed1c7e9622420a470d59ba2ec3
# docker pull nervos/ckb-riscv-gnu-toolchain:bionic-20190702
BUILDER_DOCKER := nervos/ckb-riscv-gnu-toolchain@sha256:7b168b4b109a0f741078a71b7c4dddaf1d283a5244608f7851f5714fbad273ba

all: build/generator build/validator build/blockchain.h build/godwoken.h

all-via-docker: generate-protocol
	mkdir -p build
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make"

clean-via-docker: generate-protocol
	mkdir -p build
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make clean"

build/generator: c/generator.c c/contracts.h c/generator/secp256k1_helper.h c/polyjuice.h build/secp256k1_data_info.h $(ALL_OBJS)
	cd $(SECP_DIR) && (git apply workaround-fix-g++-linking.patch || true) && cd - # apply patch
	$(CXX) $(CFLAGS) $(LDFLAGS) -Ibuild -o $@ c/generator.c $(ALL_OBJS)
	$(OBJCOPY) --only-keep-debug $@ $@.debug
	$(OBJCOPY) --strip-debug --strip-all $@
	cd $(SECP_DIR) && (git apply -R workaround-fix-g++-linking.patch || true) && cd - # revert patch

build/validator: c/validator.c c/contracts.h c/validator/secp256k1_helper.h c/polyjuice.h build/secp256k1_data_info.h $(ALL_OBJS)
	cd $(SECP_DIR) && (git apply workaround-fix-g++-linking.patch || true) && cd - # apply patch
	$(CXX) $(CFLAGS) $(LDFLAGS) -Ibuild -o $@ c/validator.c $(ALL_OBJS)
	$(OBJCOPY) --only-keep-debug $@ $@.debug
	$(OBJCOPY) --strip-debug --strip-all $@
	cd $(SECP_DIR) && (git apply -R workaround-fix-g++-linking.patch || true) && cd - # revert patch

build/evmone.o: deps/evmone/lib/evmone/evmone.cpp
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -c -o $@ $< -DPROJECT_VERSION=\"0.5.0-dev\"
build/analysis.o: deps/evmone/lib/evmone/analysis.cpp
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -c -o $@ $<
build/execution.o: deps/evmone/lib/evmone/execution.cpp
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -c -o $@ $<
build/instructions.o: deps/evmone/lib/evmone/instructions.cpp
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -c -o $@ $<
build/instructions_calls.o: deps/evmone/lib/evmone/instructions_calls.cpp
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -c -o $@ $<

build/keccak.o: deps/ethash/lib/keccak/keccak.c build/keccakf800.o build/keccakf1600.o
	$(CC) $(CFLAGS) $(LDFLAGS) -c -o $@ $<
build/keccakf1600.o: deps/ethash/lib/keccak/keccakf1600.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c -o $@ $<
build/keccakf800.o: deps/ethash/lib/keccak/keccakf800.c
	$(CC) $(CFLAGS) $(LDFLAGS)  -c -o $@ $<

build/div.o: deps/intx/lib/intx/div.cpp
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

build/blockchain.h: ${PROTOCOL_SCHEMA_DIR}/blockchain.mol
	mkdir -p build
	${MOLC} --language c --schema-file $< > $@

build/godwoken.h: ${PROTOCOL_SCHEMA_DIR}/godwoken.mol
	mkdir -p build
	${MOLC} --language c --schema-file $< > $@

clean:
	rm -rf build/*
	cd $(SECP_DIR) && [ -f "Makefile" ] && make distclean && make clean
	rm -rf $(SECP256K1_SRC)
