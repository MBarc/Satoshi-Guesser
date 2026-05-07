/*
 * Stub C wrapper for batched-inversion experiment.
 *
 * Today: just verifies the build pipeline can compile a C file and link it
 * with the rest of the Rust addon. Returns a known sentinel value.
 *
 * Next session: this file will #include libsecp256k1's internal headers
 * (group_impl.h, field_impl.h, etc.) and expose a function that performs
 * a batched walk + Montgomery-trick normalization to amortize modular
 * inversion across N intermediate points.
 */

#include <stdint.h>

/*
 * Sentinel: 0xCAFE_BABE = 3405691582. The Rust caller checks for this
 * exact value to confirm we're calling our wrapper and not some
 * accidental stub.
 */
uint32_t sgn_wrapper_sentinel(void) {
    return 0xCAFEBABEu;
}
