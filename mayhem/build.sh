#!/usr/bin/env bash
#
# apache-logging-log4cxx/mayhem/build.sh — build a focused set of log4cxx's OSS-Fuzz harnesses as
# sanitized libFuzzer targets (+ standalone reproducers), AND log4cxx's own CTest suite for
# mayhem/test.sh.
#
# Fuzzed surface (all harnesses live in src/fuzzers/cpp upstream; copies are in mayhem/harnesses/).
# We build the UTF-8 (LOG4CXX_CHAR=utf-8) encoding variant of each:
#   DOMConfiguratorFuzzer — the XML configuration parser: writes the fuzz bytes to conf.xml and calls
#                           DOMConfigurator::configure() (expat-backed XML config → appender graph).
#   PatternParserFuzzer   — the conversion-pattern parser: PatternParser::parse() over a fuzzed
#                           pattern string with the full converter rule map (%c/%d/%m/%X/...).
#   PatternLayoutFuzzer   — end-to-end: configures from PatternLayoutFuzzer.properties, then formats
#                           fuzzed log messages through a PatternLayout (the .properties config +
#                           layout formatting path).
#   TranscoderFuzzer      — the charset transcoding layer (Transcoder / CharsetDecoder /
#                           CharsetEncoder) over arbitrary bytes. This harness carries its OWN
#                           abort-on-violation round-trip oracles (UTF-8 idempotence, UTF-16BE/LE
#                           byte-encoder round trip), so it surfaces correctness defects, not just
#                           memory-safety crashes.
#
# Build contract from the org base ENV (CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE/SRC/
# STANDALONE_FUZZ_MAIN). The log4cxx library ITSELF is compiled with $SANITIZER_FLAGS (CMake flag
# injection) so the fuzzed XML/pattern/transcoder code — not just the harness — is instrumented.
#
# Strategy: upstream's src/fuzzers/cpp/CMakeLists.txt already links each fuzzer against
# $ENV{LIB_FUZZING_ENGINE} (and the correct APR/apr-util/expat link line via the Find modules) when
# LIB_FUZZING_ENGINE is set. We drive that with two CMake configures sharing one source tree:
#   pass 1: LIB_FUZZING_ENGINE=-fsanitize=fuzzer    -> /mayhem/<fuzzer>            (libFuzzer)
#   pass 2: LIB_FUZZING_ENGINE=<standalone main .o> -> /mayhem/<fuzzer>-standalone (run-once repro)
# Both reuse upstream's exact link line. The CMake target name is "<Fuzzer>-<encoding>"; we install
# it at /mayhem/<Fuzzer> (encoding suffix dropped) for stable Mayhemfile target names.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS: force DWARF ≤ 3 (§6.2 item 10; clang-19 defaults to DWARF-5 with plain -g).
: "${DEBUG_FLAGS:=-gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX MAYHEM_JOBS

cd "$SRC"

ENCODING="utf-8"
# CMake target names (upstream appends -${LOG4CXX_CHAR}); the .properties resource the
# PatternLayoutFuzzer reads next to its binary is also copied below.
FUZZERS="DOMConfiguratorFuzzer PatternParserFuzzer PatternLayoutFuzzer TranscoderFuzzer"

CXX_BUILD_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS"
C_BUILD_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS"

# ── asan_options: disable LSan to avoid ptrace conflict under Mayhem ─────────────────────────────
# Mayhem runs each target under ptrace to collect coverage; LSan also uses ptrace at exit → clash.
# Bake detect_leaks=0 into every fuzzer binary via a strong __asan_default_options symbol.
# See mayhem/asan_options.c for the full explanation.
ASAN_OPTIONS_OBJ="$SRC/mayhem-asan-options.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/asan_options.c" -o "$ASAN_OPTIONS_OBJ"

# Base CMake flags shared by both passes (compiler selection, build type, targets).
# C/CXX flags are NOT included here so each pass can set its own sanitizer mix.
CMAKE_COMMON=(
  -DCMAKE_BUILD_TYPE=RelWithDebInfo
  -DBUILD_SHARED_LIBS=OFF
  -DBUILD_TESTING=OFF
  -DBUILD_EXAMPLES=OFF
  -DBUILD_FUZZERS=ON
  -DLOG4CXX_CHAR="$ENCODING"
  -DCMAKE_C_COMPILER="$CC"
  -DCMAKE_CXX_COMPILER="$CXX"
)

cmake_targets() { for f in $FUZZERS; do echo "$f-$ENCODING"; done; }

# ── pass 1: libFuzzer targets ────────────────────────────────────────────────────────────────────
# Add -fsanitize=fuzzer-no-link so the log4cxx library AND each harness TU gets libFuzzer's
# SanitizerCoverage edge instrumentation.  Without it the library is compiled with ASan/UBSan
# only → no coverage feedback → 0 edges on every run.  The fuzzer runtime itself comes from
# LIB_FUZZING_ENGINE=-fsanitize=fuzzer (linked by upstream's CMakeLists.txt).
export LIB_FUZZING_ENGINE="-fsanitize=fuzzer"
BUILD_FUZZ="$SRC/mayhem-build-fuzz"
rm -rf "$BUILD_FUZZ"; mkdir -p "$BUILD_FUZZ"
( cd "$BUILD_FUZZ" && cmake "$SRC" "${CMAKE_COMMON[@]}" \
    -DCMAKE_C_FLAGS="$C_BUILD_FLAGS -fsanitize=fuzzer-no-link" \
    -DCMAKE_CXX_FLAGS="$CXX_BUILD_FLAGS -fsanitize=fuzzer-no-link" \
    -DCMAKE_EXE_LINKER_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS $ASAN_OPTIONS_OBJ" )
make -C "$BUILD_FUZZ" -j"$MAYHEM_JOBS" $(cmake_targets)
for f in $FUZZERS; do
  src_bin="$(find "$BUILD_FUZZ/src/fuzzers/cpp" -maxdepth 1 -type f -name "$f-$ENCODING" | head -1)"
  cp "$src_bin" "/mayhem/$f"
  echo "built libFuzzer target /mayhem/$f"
done

# ── pass 2: standalone reproducers ───────────────────────────────────────────────────────────────
# Compile the run-once standalone main (C) as an object, then re-link the SAME harnesses against it
# by pointing LIB_FUZZING_ENGINE at the object instead of libFuzzer.
SA_OBJ="$SRC/mayhem-standalone-main.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$SA_OBJ"
export LIB_FUZZING_ENGINE="$SA_OBJ"
BUILD_SA="$SRC/mayhem-build-standalone"
rm -rf "$BUILD_SA"; mkdir -p "$BUILD_SA"
( cd "$BUILD_SA" && cmake "$SRC" "${CMAKE_COMMON[@]}" \
    -DCMAKE_C_FLAGS="$C_BUILD_FLAGS" \
    -DCMAKE_CXX_FLAGS="$CXX_BUILD_FLAGS" \
    -DCMAKE_EXE_LINKER_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS $ASAN_OPTIONS_OBJ" )
make -C "$BUILD_SA" -j"$MAYHEM_JOBS" $(cmake_targets)
for f in $FUZZERS; do
  src_bin="$(find "$BUILD_SA/src/fuzzers/cpp" -maxdepth 1 -type f -name "$f-$ENCODING" | head -1)"
  cp "$src_bin" "/mayhem/$f-standalone"
  echo "built standalone reproducer /mayhem/$f-standalone"
done

# PatternLayoutFuzzer reads PatternLayoutFuzzer.properties from its own directory (chdir to exe home).
cp "$SRC/mayhem/resources/PatternLayoutFuzzer.properties" /mayhem/PatternLayoutFuzzer.properties

# ── test suite: build log4cxx's OWN CTest suite with NORMAL flags (no sanitizers) so test.sh is an
#    honest PATCH oracle and only RUNS the pre-built suite. Separate tree. ─────────────────────────
BUILD_TESTS="$SRC/mayhem-tests"
rm -rf "$BUILD_TESTS"; mkdir -p "$BUILD_TESTS"
env -u CFLAGS -u CXXFLAGS -u SANITIZER_FLAGS \
  cmake -S "$SRC" -B "$BUILD_TESTS" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DBUILD_SHARED_LIBS=OFF \
    -DBUILD_TESTING=ON \
    -DBUILD_EXAMPLES=OFF \
    -DBUILD_FUZZERS=OFF \
    -DLOG4CXX_CHAR="$ENCODING" \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_CXX_COMPILER="$CXX"
env -u CFLAGS -u CXXFLAGS -u SANITIZER_FLAGS \
  cmake --build "$BUILD_TESTS" -j"$MAYHEM_JOBS"
echo "built log4cxx CTest suite in mayhem-tests/"

# ── oracle_test: behavioral test binary for mayhem/test.sh (compiled against the test-suite build)
# Greps for known output strings; a no-op/exit(0) patch produces no output and fails the grep.
LOG4CXX_LIB="$BUILD_TESTS/src/main/cpp/liblog4cxx.a"
LOG4CXX_INCLUDE_SRC="$SRC/src/main/include"
LOG4CXX_INCLUDE_BUILD="$BUILD_TESTS/src/main/include"
env -u CFLAGS -u CXXFLAGS -u SANITIZER_FLAGS \
  "$CXX" -std=c++17 \
    -I"$LOG4CXX_INCLUDE_SRC" -I"$LOG4CXX_INCLUDE_BUILD" \
    "$SRC/mayhem/harnesses/oracle_test.cpp" \
    "$LOG4CXX_LIB" \
    -laprutil-1 -lapr-1 -lexpat -lpthread \
    -o /mayhem/oracle-test
echo "built behavioral oracle /mayhem/oracle-test"

echo "build.sh complete:"
ls -la /mayhem/DOMConfiguratorFuzzer /mayhem/PatternParserFuzzer \
       /mayhem/PatternLayoutFuzzer /mayhem/TranscoderFuzzer \
       /mayhem/DOMConfiguratorFuzzer-standalone /mayhem/PatternParserFuzzer-standalone \
       /mayhem/PatternLayoutFuzzer-standalone /mayhem/TranscoderFuzzer-standalone 2>&1 || true
