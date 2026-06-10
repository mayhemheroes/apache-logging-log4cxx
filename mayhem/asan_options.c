/*
 * apache-logging-log4cxx/mayhem/asan_options.c — ASan runtime option overrides.
 *
 * LeakSanitizer (LSan) is enabled by default when building with
 * -fsanitize=address on Linux.  LSan works by ptrace-attaching to its own
 * threads at process exit to scan for leaks.  Mayhem's coverage-collection
 * mode ALREADY runs the target under ptrace, and Linux allows only ONE tracer
 * per process.  When LSan tries to attach, it fails with:
 *
 *   "LeakSanitizer has encountered a fatal error … does not work under
 *    ptrace (strace, gdb, etc.)"
 *
 * and the process exits 1 BEFORE any edges are recorded → 0-edge "Run Failed"
 * for every target.  The binaries run fine standalone (fuzz-smoke, local tests)
 * but fail only under the real Mayhem coverage run.
 *
 * Fix: export detect_leaks=0 via __asan_default_options (baked into the binary
 * at link time) so LSan is never activated at runtime.  Real memory-safety bugs
 * — heap overflows, use-after-free, UBSan violations — are still caught by the
 * non-LSan parts of ASan.  Leak detection is not useful for short-lived fuzzing
 * iterations anyway.
 *
 * A strong (non-weak) definition is used here to win over the ASan runtime's
 * own weak copy even when ASan-instrumented shared libraries are linked in.
 * Linked into every fuzzer binary via ASAN_OPTIONS_OBJ in mayhem/build.sh.
 */
const char *__asan_default_options(void)
{
    return "detect_leaks=0";
}
