# TARGET := riscv64-unknown-linux-gnu
TARGET := riscv64-unknown-elf
CC := $(TARGET)-gcc
CXX := $(TARGET)-g++
LD := $(TARGET)-gcc
OBJCOPY := $(TARGET)-objcopy

CFLAGS_CKB_STD = -Ideps/ckb-c-stdlib -Ideps/ckb-c-stdlib/molecule
# CFLAGS_CBMT := -isystem deps/merkle-tree
CFLAGS_INTX := -Ideps/intx/lib/intx -Ideps/intx/include
CFLAGS_ETHASH := -Ideps/ethash/include -Ideps/ethash/lib/ethash -Ideps/ethash/lib/keccak -Ideps/ethash/lib/support
CFLAGS_EVMONE := -Ideps/evmone/lib/evmone -Ideps/evmone/include -Ideps/evmone/evmc/include
CFLAGS_GODWOKEN := -Ideps/godwoken/c
CFLAGS := -O3 -Ic $(CFLAGS_CKB_STD) $(CFLAGS_EVMONE) $(CFLAGS_INTX) $(CFLAGS_ETHASH) $(CFLAGS_GODWOKEN) -Wall -g
CXXFLAGS := $(CFLAGS) -std=c++1z
LDFLAGS := -fdata-sections -ffunction-sections -Wl,--gc-sections

MOLC := moleculec
MOLC_VERSION := 0.6.1
PROTOCOL_SCHEMA_DIR := ./deps/godwoken/crates/types/schemas

ALL_OBJS := build/evmone.o build/analysis.o build/execution.o build/instructions.o build/instructions_calls.o build/div.o build/keccak.o build/keccakf800.o build/keccakf1600.o

# docker pull nervos/ckb-riscv-gnu-toolchain:gnu-bionic-20191012
# BUILDER_DOCKER := nervos/ckb-riscv-gnu-toolchain@sha256:aae8a3f79705f67d505d1f1d5ddc694a4fd537ed1c7e9622420a470d59ba2ec3
# docker pull nervos/ckb-riscv-gnu-toolchain:bionic-20190702
BUILDER_DOCKER := nervos/ckb-riscv-gnu-toolchain@sha256:7b168b4b109a0f741078a71b7c4dddaf1d283a5244608f7851f5714fbad273ba

all: build/generator build/blockchain.h build/godwoken.h

all-via-docker: generate-protocol
	mkdir -p build
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make"

build/generator: c/generator.c c/polyjuice.h $(ALL_OBJS)
	$(CXX) $(CFLAGS) $(LDFLAGS) -I. -Ibuild -o $@ c/generator.c $(ALL_OBJS)
	$(OBJCOPY) --only-keep-debug $@ $@.debug
	$(OBJCOPY) --strip-debug --strip-all $@

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


generate-protocol: check-moleculec-version build/blockchain.h build/godwoken.h
check-moleculec-version:
	test "$$(${MOLC} --version | awk '{ print $$2 }' | tr -d ' ')" = ${MOLC_VERSION}

build/blockchain.h: ${PROTOCOL_SCHEMA_DIR}/blockchain.mol
	${MOLC} --language c --schema-file $< > $@

build/godwoken.h: ${PROTOCOL_SCHEMA_DIR}/godwoken.mol
	${MOLC} --language c --schema-file $< > $@

clean:
	rm -rf build/*
