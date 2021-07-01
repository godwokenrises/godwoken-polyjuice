# Polyjuice Fuzz Test


## Polyjuice Generator Fuzzer
```bash
make build/polyjuice_generator_fuzzer
./build/polyjuice_generator_fuzzer
```

```log
```

### General Algorithm
```pseudo code
// pseudo code
Instrument program for code coverage
load pre-defined transactions such as contracts deploying and then execute run_polyjuice()
while(true) {
  Choose random input from corpus
  Mutate/populate input into transactions
  Execute run_polyjuice() and collect coverage
  If new coverage/paths are hit add it to corpus (corpus - directory with test-cases)
}
```

## test_contracts on x86 with [sanitizers](https://github.com/google/sanitizers)
```bash
make build/test_contracts
./build/test_contracts

make build/test_rlp
./build/test_rlp
```

## Coverage Report[WIP]
TBD

### Related materials
- https://llvm.org/docs/LibFuzzer.html
- [What makes a good fuzz target](https://github.com/google/fuzzing/blob/master/docs/good-fuzz-target.md)
- [Clang's source-based code coverage](https://clang.llvm.org/docs/SourceBasedCodeCoverage.html)
