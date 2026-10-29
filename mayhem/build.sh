#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# UBSan relaxation (recorded in the PR): MNN casts function pointers between signatures throughout its CPU
# kernels (e.g. CPUPool.cpp, CPUUnary.cpp), which -fsanitize=function halts on for every model that
# contains such an op. Every other ASan/UBSan check stays on and halting.
FUZZ_SAN="$SANITIZER_FLAGS -fno-sanitize=function"

# libFuzzer edge coverage inside the library itself (the harnesses are tiny; all interesting edges are in MNN).
LIB_COVERAGE="-fsanitize=fuzzer-no-link"

# 1) Build MNN as a static library with the sanitizer + DWARF<=3 flags (the fuzzed code is instrumented).
#    Out-of-source build dirs live under build/ (gitignored upstream, so `git clean -ffdX` removes them).
#    MNN_BUILD_OPENCV+MNN_IMGCODECS pull in the stb_image based decoder; everything is vendored in-tree,
#    so the build needs no network.
# MNN_FORBID_MULTI_THREAD runs tasks inline: deterministic for fuzzing, and avoids MNN calling ThreadPool::enqueue
#    through a null pool when the runtime has one thread (UBSan halts on that).
rm -rf "$SRC/build/fuzz"
cmake -S "$SRC" -B "$SRC/build/fuzz" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_C_FLAGS="$FUZZ_SAN $DEBUG_FLAGS $LIB_COVERAGE" \
    -DCMAKE_CXX_FLAGS="$FUZZ_SAN $DEBUG_FLAGS $LIB_COVERAGE" \
    -DMNN_BUILD_SHARED_LIBS=OFF -DMNN_SEP_BUILD=OFF -DMNN_BUILD_TOOLS=OFF -DMNN_BUILD_TEST=OFF \
    -DMNN_BUILD_OPENCV=ON -DMNN_IMGCODECS=ON -DMNN_USE_LOGCAT=OFF \
    -DMNN_FORBID_MULTI_THREAD=ON \
    -DMNN_AVX512=OFF -DMNN_ARM82=OFF -DMNN_SME2=OFF
cmake --build "$SRC/build/fuzz" -j"$MAYHEM_JOBS" --target MNN
MNN_LIB="$SRC/build/fuzz/libMNN.a"

# 2) Each harness twice: libFuzzer binary + standalone run-once reproducer. LSan is turned off at link
#    time via lsan_off.cc. MNN registers its ops/backends from static initializers, so the archive must
#    be linked whole.
HCXXFLAGS="-std=c++17 -fno-rtti $FUZZ_SAN $DEBUG_FLAGS -I$SRC/include -I$SRC/tools/cv/include"
$CC $FUZZ_SAN $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o /tmp/standalone_main.o
$CXX $FUZZ_SAN $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o /tmp/lsan_off.o
for h in fuzz_interpreter fuzz_module fuzz_imdecode; do
    $CXX $HCXXFLAGS $LIB_FUZZING_ENGINE "$SRC/mayhem/harnesses/$h.cc" /tmp/lsan_off.o \
        -Wl,--whole-archive "$MNN_LIB" -Wl,--no-whole-archive -lpthread -ldl \
        -o "/mayhem/$h"
    $CXX $HCXXFLAGS "$SRC/mayhem/harnesses/$h.cc" /tmp/standalone_main.o /tmp/lsan_off.o \
        -Wl,--whole-archive "$MNN_LIB" -Wl,--no-whole-archive -lpthread -ldl \
        -o "/mayhem/$h-standalone"
done

# 3) The project's own unit-test runner (run_test.out), built with NORMAL flags in a separate tree.
rm -rf "$SRC/build/test"
env -u CFLAGS -u CXXFLAGS -u LDFLAGS cmake -S "$SRC" -B "$SRC/build/test" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS" \
    -DMNN_BUILD_SHARED_LIBS=OFF -DMNN_SEP_BUILD=OFF -DMNN_BUILD_TOOLS=OFF -DMNN_BUILD_TEST=ON \
    -DMNN_USE_LOGCAT=OFF -DMNN_AVX512=OFF -DMNN_ARM82=OFF -DMNN_SME2=OFF
cmake --build "$SRC/build/test" -j"$MAYHEM_JOBS" --target run_test.out
