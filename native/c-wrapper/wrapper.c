/*
 * c-wrapper for Satoshi Guesser native addon.
 *
 * Exposes:
 *   - sgn_wrapper_sentinel():        build-pipeline check (returns 0xCAFEBABE)
 *   - sgn_compute_affine_batch():    libsecp256k1-internal scalar mult +
 *                                    Jacobian walk + Montgomery batch invert.
 *                                    Writes N × 64 bytes (32 byte BE x ||
 *                                    32 byte BE y) to caller's buffer.
 *                                    Kept for tests and as a fallback.
 *   - ripemd160_8way():              8-way AVX2 RIPEMD-160. 8 independent
 *                                    32-byte inputs -> 8 × 20-byte outputs.
 *                                    Kept for tests and as a fallback.
 *   - sha256_pubkey_ni():            SHA-NI single-input two-block compress
 *                                    over a 65-byte uncompressed pubkey ->
 *                                    32-byte digest. Uses _mm_sha256rnds2 +
 *                                    _mm_sha256msg1/2 intrinsics.
 *   - sgn_set_targets():             Loads N × 20-byte target h160s into a
 *                                    process-global open-addressing table.
 *   - sgn_search_batch():            Unified hot path. Takes k0_bytes + n,
 *                                    runs EC batch + SHA-NI + 8-way RIPEMD +
 *                                    target lookup all in C. On match, fills
 *                                    out_match with priv_offset + h160 and
 *                                    returns 1. On clean run, returns 0 with
 *                                    keys_checked == n.
 *
 * Hot-path consolidation: everything between random k0 and "found / not found"
 * runs inside a single C function, eliminating per-chunk Rust↔C dispatch and
 * keeping the entire pipeline in one compilation unit so the compiler can
 * inline aggressively. SHA-NI replaces the prior call-back-into-Rust sha2
 * crate path; identical hardware acceleration, no FFI per candidate.
 *
 * RIPEMD-160 spec:
 *   https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
 * Intel SHA Extensions reference:
 *   https://www.intel.com/content/dam/develop/external/us/en/documents/intel-sha-extensions-white-paper-402097.pdf
 */

#include <stdint.h>
#include <string.h>

/* ===============================================================
 * Sentinel — kept for the existing Rust c_wrapper_alive() check
 * =============================================================== */

uint32_t sgn_wrapper_sentinel(void) {
    return 0xCAFEBABEu;
}

/* ===============================================================
 * libsecp256k1 unity build + EC batch function
 *
 * Including secp256k1.c (and the precomputed-table .c files) here gives us
 * inline access to the internal *_impl.h functions: secp256k1_gej_add_ge_var,
 * secp256k1_fe_inv, secp256k1_ecmult_gen, secp256k1_ge_const_g, etc. The
 * build defines (ECMULT_WINDOW_SIZE, ECMULT_GEN_PREC_BITS, USE_FIELD_5X52,
 * USE_SCALAR_4X64) come from build.rs.
 * =============================================================== */

#include "libsecp256k1/src/secp256k1.c"
#include "libsecp256k1/src/precomputed_ecmult.c"
#include "libsecp256k1/src/precomputed_ecmult_gen.c"

#define SGN_MAX_BATCH 16384

/* Per-thread scratch arrays. Node worker_threads share the addon's address
 * space, so a plain `static` here would race. _Thread_local gives each
 * worker its own private buffers. ~1.7 MB per thread; 4 threads = ~6.8 MB. */
#if defined(_MSC_VER)
#define SGN_THREAD_LOCAL __declspec(thread)
#else
#define SGN_THREAD_LOCAL _Thread_local
#endif

static SGN_THREAD_LOCAL secp256k1_gej g_chain[SGN_MAX_BATCH];
static SGN_THREAD_LOCAL secp256k1_fe  g_zinv[SGN_MAX_BATCH];
static SGN_THREAD_LOCAL secp256k1_fe  g_zacc[SGN_MAX_BATCH];

/* The ecmult_gen context is per-thread; built lazily on first call.
 * `built` is a tristate-as-int, but C11 _Thread_local zero-initializes,
 * so the first call sees built==0 and runs context_build. */
typedef struct {
    secp256k1_ecmult_gen_context ctx;
    int built;
} sgn_gen_state_t;

static SGN_THREAD_LOCAL sgn_gen_state_t g_gen_state;

/* Compute (k0+i)*G's affine x/y for i=0..n-1 and write them into out_xy
 * as N × 64 bytes: each block is 32 bytes BE x || 32 bytes BE y. Returns
 * 1 on success, 0 if k0 is out-of-range or zero (output left zeroed in
 * that case so callers see no false positives). */
int sgn_compute_affine_batch(
    const uint8_t* k0_bytes,
    uint32_t n,
    uint8_t* out_xy
) {
    if (n == 0 || n > SGN_MAX_BATCH) return 0;

    if (!g_gen_state.built) {
        secp256k1_ecmult_gen_context_build(&g_gen_state.ctx);
        g_gen_state.built = 1;
    }

    secp256k1_scalar k0;
    int overflow = 0;
    secp256k1_scalar_set_b32(&k0, k0_bytes, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&k0)) {
        memset(out_xy, 0, (size_t)n * 64);
        return 0;
    }

    /* P0 = k0 * G via libsecp's precomputed-table ecmult. */
    secp256k1_ecmult_gen(&g_gen_state.ctx, &g_chain[0], &k0);

    /* P_(i+1) = P_i + G via mixed Jacobian+affine, no inversion. */
    for (uint32_t i = 1; i < n; i++) {
        secp256k1_gej_add_ge_var(&g_chain[i], &g_chain[i - 1], &secp256k1_ge_const_g, NULL);
    }

    /* Montgomery batch invert: 1 fe_inv + 3*(N-1) fe_mul instead of N fe_inv. */
    g_zacc[0] = g_chain[0].z;
    for (uint32_t i = 1; i < n; i++) {
        secp256k1_fe_mul(&g_zacc[i], &g_zacc[i - 1], &g_chain[i].z);
    }
    secp256k1_fe acc_inv;
    secp256k1_fe_inv(&acc_inv, &g_zacc[n - 1]);
    for (uint32_t i = n - 1; i > 0; i--) {
        secp256k1_fe_mul(&g_zinv[i], &acc_inv, &g_zacc[i - 1]);
        secp256k1_fe_mul(&acc_inv, &acc_inv, &g_chain[i].z);
    }
    g_zinv[0] = acc_inv;

    /* Convert each to affine and write out 32+32 BE bytes. */
    for (uint32_t i = 0; i < n; i++) {
        secp256k1_fe z2, z3, x, y;
        secp256k1_fe_sqr(&z2, &g_zinv[i]);
        secp256k1_fe_mul(&z3, &z2, &g_zinv[i]);
        secp256k1_fe_mul(&x, &g_chain[i].x, &z2);
        secp256k1_fe_mul(&y, &g_chain[i].y, &z3);
        secp256k1_fe_normalize_var(&x);
        secp256k1_fe_normalize_var(&y);
        secp256k1_fe_get_b32(out_xy + (size_t)i * 64,      &x);
        secp256k1_fe_get_b32(out_xy + (size_t)i * 64 + 32, &y);
    }
    return 1;
}

/* ===============================================================
 * 8-way AVX2 RIPEMD-160
 * =============================================================== */

#if defined(__AVX2__)

#include <immintrin.h>

#define ROL(x, n) _mm256_or_si256(_mm256_slli_epi32((x), (n)), _mm256_srli_epi32((x), 32 - (n)))

#define NOT(x) _mm256_xor_si256((x), _mm256_set1_epi32(-1))

/* RIPEMD-160 nonlinear functions */
#define F0(b, c, d) _mm256_xor_si256(_mm256_xor_si256((b), (c)), (d))
#define F1(b, c, d) _mm256_or_si256(_mm256_and_si256((b), (c)), _mm256_andnot_si256((b), (d)))
#define F2(b, c, d) _mm256_xor_si256(_mm256_or_si256((b), NOT(c)), (d))
#define F3(b, c, d) _mm256_or_si256(_mm256_and_si256((b), (d)), _mm256_andnot_si256((d), (c)))
#define F4(b, c, d) _mm256_xor_si256((b), _mm256_or_si256((c), NOT(d)))

#define ADD3(a, b, c) _mm256_add_epi32(_mm256_add_epi32((a), (b)), (c))
#define ADD4(a, b, c, d) _mm256_add_epi32(ADD3((a), (b), (c)), (d))

/* One round of either line. F is the nonlinear function macro, K is the
 * 32-bit round constant, R is the message-word index, S is the rotation
 * amount, and STATE is one of the two state-rotate steps written inline. */
#define ROUND(A, B, C, D, E, F, K, R, S) do {                                  \
    __m256i T = ADD4((A), F((B), (C), (D)), X[(R)], _mm256_set1_epi32((int)(K))); \
    T = _mm256_add_epi32(ROL(T, (S)), (E));                                    \
    (A) = (E); (E) = (D); (D) = ROL((C), 10); (C) = (B); (B) = T;              \
} while (0)

/* Transpose 8x8 32-bit words. Inputs a0..a7 each hold one source's 8 words
 * in lane-order. Outputs t0..t7 hold word i from each of the 8 sources. */
static inline void transpose_8x8(
    __m256i a0, __m256i a1, __m256i a2, __m256i a3,
    __m256i a4, __m256i a5, __m256i a6, __m256i a7,
    __m256i out[8]
) {
    __m256i s0 = _mm256_unpacklo_epi32(a0, a1);
    __m256i s1 = _mm256_unpackhi_epi32(a0, a1);
    __m256i s2 = _mm256_unpacklo_epi32(a2, a3);
    __m256i s3 = _mm256_unpackhi_epi32(a2, a3);
    __m256i s4 = _mm256_unpacklo_epi32(a4, a5);
    __m256i s5 = _mm256_unpackhi_epi32(a4, a5);
    __m256i s6 = _mm256_unpacklo_epi32(a6, a7);
    __m256i s7 = _mm256_unpackhi_epi32(a6, a7);

    __m256i u0 = _mm256_unpacklo_epi64(s0, s2);
    __m256i u1 = _mm256_unpackhi_epi64(s0, s2);
    __m256i u2 = _mm256_unpacklo_epi64(s1, s3);
    __m256i u3 = _mm256_unpackhi_epi64(s1, s3);
    __m256i u4 = _mm256_unpacklo_epi64(s4, s6);
    __m256i u5 = _mm256_unpackhi_epi64(s4, s6);
    __m256i u6 = _mm256_unpacklo_epi64(s5, s7);
    __m256i u7 = _mm256_unpackhi_epi64(s5, s7);

    out[0] = _mm256_permute2x128_si256(u0, u4, 0x20);
    out[1] = _mm256_permute2x128_si256(u1, u5, 0x20);
    out[2] = _mm256_permute2x128_si256(u2, u6, 0x20);
    out[3] = _mm256_permute2x128_si256(u3, u7, 0x20);
    out[4] = _mm256_permute2x128_si256(u0, u4, 0x31);
    out[5] = _mm256_permute2x128_si256(u1, u5, 0x31);
    out[6] = _mm256_permute2x128_si256(u2, u6, 0x31);
    out[7] = _mm256_permute2x128_si256(u3, u7, 0x31);
}

/* Process exactly 32 bytes per input. RIPEMD-160 reads message words in
 * little-endian, which matches the natural byte order of x86 32-bit loads. */
void ripemd160_8way(const uint8_t* in_8x32, uint8_t* out_8x20) {
    /* Load 8 inputs (32 bytes each) into 8 registers, then transpose so
     * X[i] holds word i from each input. */
    __m256i a0 = _mm256_loadu_si256((const __m256i*)(in_8x32 + 0  * 32));
    __m256i a1 = _mm256_loadu_si256((const __m256i*)(in_8x32 + 1  * 32));
    __m256i a2 = _mm256_loadu_si256((const __m256i*)(in_8x32 + 2  * 32));
    __m256i a3 = _mm256_loadu_si256((const __m256i*)(in_8x32 + 3  * 32));
    __m256i a4 = _mm256_loadu_si256((const __m256i*)(in_8x32 + 4  * 32));
    __m256i a5 = _mm256_loadu_si256((const __m256i*)(in_8x32 + 5  * 32));
    __m256i a6 = _mm256_loadu_si256((const __m256i*)(in_8x32 + 6  * 32));
    __m256i a7 = _mm256_loadu_si256((const __m256i*)(in_8x32 + 7  * 32));

    __m256i X[16];
    transpose_8x8(a0, a1, a2, a3, a4, a5, a6, a7, X);

    /* Padding for a 32-byte message: byte 32 = 0x80, bytes 33..55 = 0,
     * bytes 56..63 = length-in-bits little-endian (256). */
    X[8]  = _mm256_set1_epi32(0x00000080);
    X[9]  = _mm256_setzero_si256();
    X[10] = _mm256_setzero_si256();
    X[11] = _mm256_setzero_si256();
    X[12] = _mm256_setzero_si256();
    X[13] = _mm256_setzero_si256();
    X[14] = _mm256_set1_epi32(256);
    X[15] = _mm256_setzero_si256();

    /* Initial state — same for all 8 hashes */
    const __m256i IV0 = _mm256_set1_epi32((int)0x67452301);
    const __m256i IV1 = _mm256_set1_epi32((int)0xefcdab89);
    const __m256i IV2 = _mm256_set1_epi32((int)0x98badcfe);
    const __m256i IV3 = _mm256_set1_epi32((int)0x10325476);
    const __m256i IV4 = _mm256_set1_epi32((int)0xc3d2e1f0);

    __m256i al = IV0, bl = IV1, cl = IV2, dl = IV3, el = IV4;
    __m256i ar = IV0, br = IV1, cr = IV2, dr = IV3, er = IV4;

    /* ===== LEFT LINE ===== */
    /* Round 0..15: F0, K = 0 */
    ROUND(al, bl, cl, dl, el, F0, 0u, 0,  11);
    ROUND(al, bl, cl, dl, el, F0, 0u, 1,  14);
    ROUND(al, bl, cl, dl, el, F0, 0u, 2,  15);
    ROUND(al, bl, cl, dl, el, F0, 0u, 3,  12);
    ROUND(al, bl, cl, dl, el, F0, 0u, 4,  5);
    ROUND(al, bl, cl, dl, el, F0, 0u, 5,  8);
    ROUND(al, bl, cl, dl, el, F0, 0u, 6,  7);
    ROUND(al, bl, cl, dl, el, F0, 0u, 7,  9);
    ROUND(al, bl, cl, dl, el, F0, 0u, 8,  11);
    ROUND(al, bl, cl, dl, el, F0, 0u, 9,  13);
    ROUND(al, bl, cl, dl, el, F0, 0u, 10, 14);
    ROUND(al, bl, cl, dl, el, F0, 0u, 11, 15);
    ROUND(al, bl, cl, dl, el, F0, 0u, 12, 6);
    ROUND(al, bl, cl, dl, el, F0, 0u, 13, 7);
    ROUND(al, bl, cl, dl, el, F0, 0u, 14, 9);
    ROUND(al, bl, cl, dl, el, F0, 0u, 15, 8);

    /* Round 16..31: F1, K = 0x5A827999 */
    ROUND(al, bl, cl, dl, el, F1, 0x5A827999u, 7,  7);
    ROUND(al, bl, cl, dl, el, F1, 0x5A827999u, 4,  6);
    ROUND(al, bl, cl, dl, el, F1, 0x5A827999u, 13, 8);
    ROUND(al, bl, cl, dl, el, F1, 0x5A827999u, 1,  13);
    ROUND(al, bl, cl, dl, el, F1, 0x5A827999u, 10, 11);
    ROUND(al, bl, cl, dl, el, F1, 0x5A827999u, 6,  9);
    ROUND(al, bl, cl, dl, el, F1, 0x5A827999u, 15, 7);
    ROUND(al, bl, cl, dl, el, F1, 0x5A827999u, 3,  15);
    ROUND(al, bl, cl, dl, el, F1, 0x5A827999u, 12, 7);
    ROUND(al, bl, cl, dl, el, F1, 0x5A827999u, 0,  12);
    ROUND(al, bl, cl, dl, el, F1, 0x5A827999u, 9,  15);
    ROUND(al, bl, cl, dl, el, F1, 0x5A827999u, 5,  9);
    ROUND(al, bl, cl, dl, el, F1, 0x5A827999u, 2,  11);
    ROUND(al, bl, cl, dl, el, F1, 0x5A827999u, 14, 7);
    ROUND(al, bl, cl, dl, el, F1, 0x5A827999u, 11, 13);
    ROUND(al, bl, cl, dl, el, F1, 0x5A827999u, 8,  12);

    /* Round 32..47: F2, K = 0x6ED9EBA1 */
    ROUND(al, bl, cl, dl, el, F2, 0x6ED9EBA1u, 3,  11);
    ROUND(al, bl, cl, dl, el, F2, 0x6ED9EBA1u, 10, 13);
    ROUND(al, bl, cl, dl, el, F2, 0x6ED9EBA1u, 14, 6);
    ROUND(al, bl, cl, dl, el, F2, 0x6ED9EBA1u, 4,  7);
    ROUND(al, bl, cl, dl, el, F2, 0x6ED9EBA1u, 9,  14);
    ROUND(al, bl, cl, dl, el, F2, 0x6ED9EBA1u, 15, 9);
    ROUND(al, bl, cl, dl, el, F2, 0x6ED9EBA1u, 8,  13);
    ROUND(al, bl, cl, dl, el, F2, 0x6ED9EBA1u, 1,  15);
    ROUND(al, bl, cl, dl, el, F2, 0x6ED9EBA1u, 2,  14);
    ROUND(al, bl, cl, dl, el, F2, 0x6ED9EBA1u, 7,  8);
    ROUND(al, bl, cl, dl, el, F2, 0x6ED9EBA1u, 0,  13);
    ROUND(al, bl, cl, dl, el, F2, 0x6ED9EBA1u, 6,  6);
    ROUND(al, bl, cl, dl, el, F2, 0x6ED9EBA1u, 13, 5);
    ROUND(al, bl, cl, dl, el, F2, 0x6ED9EBA1u, 11, 12);
    ROUND(al, bl, cl, dl, el, F2, 0x6ED9EBA1u, 5,  7);
    ROUND(al, bl, cl, dl, el, F2, 0x6ED9EBA1u, 12, 5);

    /* Round 48..63: F3, K = 0x8F1BBCDC */
    ROUND(al, bl, cl, dl, el, F3, 0x8F1BBCDCu, 1,  11);
    ROUND(al, bl, cl, dl, el, F3, 0x8F1BBCDCu, 9,  12);
    ROUND(al, bl, cl, dl, el, F3, 0x8F1BBCDCu, 11, 14);
    ROUND(al, bl, cl, dl, el, F3, 0x8F1BBCDCu, 10, 15);
    ROUND(al, bl, cl, dl, el, F3, 0x8F1BBCDCu, 0,  14);
    ROUND(al, bl, cl, dl, el, F3, 0x8F1BBCDCu, 8,  15);
    ROUND(al, bl, cl, dl, el, F3, 0x8F1BBCDCu, 12, 9);
    ROUND(al, bl, cl, dl, el, F3, 0x8F1BBCDCu, 4,  8);
    ROUND(al, bl, cl, dl, el, F3, 0x8F1BBCDCu, 13, 9);
    ROUND(al, bl, cl, dl, el, F3, 0x8F1BBCDCu, 3,  14);
    ROUND(al, bl, cl, dl, el, F3, 0x8F1BBCDCu, 7,  5);
    ROUND(al, bl, cl, dl, el, F3, 0x8F1BBCDCu, 15, 6);
    ROUND(al, bl, cl, dl, el, F3, 0x8F1BBCDCu, 14, 8);
    ROUND(al, bl, cl, dl, el, F3, 0x8F1BBCDCu, 5,  6);
    ROUND(al, bl, cl, dl, el, F3, 0x8F1BBCDCu, 6,  5);
    ROUND(al, bl, cl, dl, el, F3, 0x8F1BBCDCu, 2,  12);

    /* Round 64..79: F4, K = 0xA953FD4E */
    ROUND(al, bl, cl, dl, el, F4, 0xA953FD4Eu, 4,  9);
    ROUND(al, bl, cl, dl, el, F4, 0xA953FD4Eu, 0,  15);
    ROUND(al, bl, cl, dl, el, F4, 0xA953FD4Eu, 5,  5);
    ROUND(al, bl, cl, dl, el, F4, 0xA953FD4Eu, 9,  11);
    ROUND(al, bl, cl, dl, el, F4, 0xA953FD4Eu, 7,  6);
    ROUND(al, bl, cl, dl, el, F4, 0xA953FD4Eu, 12, 8);
    ROUND(al, bl, cl, dl, el, F4, 0xA953FD4Eu, 2,  13);
    ROUND(al, bl, cl, dl, el, F4, 0xA953FD4Eu, 10, 12);
    ROUND(al, bl, cl, dl, el, F4, 0xA953FD4Eu, 14, 5);
    ROUND(al, bl, cl, dl, el, F4, 0xA953FD4Eu, 1,  12);
    ROUND(al, bl, cl, dl, el, F4, 0xA953FD4Eu, 3,  13);
    ROUND(al, bl, cl, dl, el, F4, 0xA953FD4Eu, 8,  14);
    ROUND(al, bl, cl, dl, el, F4, 0xA953FD4Eu, 11, 11);
    ROUND(al, bl, cl, dl, el, F4, 0xA953FD4Eu, 6,  8);
    ROUND(al, bl, cl, dl, el, F4, 0xA953FD4Eu, 15, 5);
    ROUND(al, bl, cl, dl, el, F4, 0xA953FD4Eu, 13, 6);

    /* ===== RIGHT LINE ===== */
    /* Round 0..15: F4, K = 0x50A28BE6 */
    ROUND(ar, br, cr, dr, er, F4, 0x50A28BE6u, 5,  8);
    ROUND(ar, br, cr, dr, er, F4, 0x50A28BE6u, 14, 9);
    ROUND(ar, br, cr, dr, er, F4, 0x50A28BE6u, 7,  9);
    ROUND(ar, br, cr, dr, er, F4, 0x50A28BE6u, 0,  11);
    ROUND(ar, br, cr, dr, er, F4, 0x50A28BE6u, 9,  13);
    ROUND(ar, br, cr, dr, er, F4, 0x50A28BE6u, 2,  15);
    ROUND(ar, br, cr, dr, er, F4, 0x50A28BE6u, 11, 15);
    ROUND(ar, br, cr, dr, er, F4, 0x50A28BE6u, 4,  5);
    ROUND(ar, br, cr, dr, er, F4, 0x50A28BE6u, 13, 7);
    ROUND(ar, br, cr, dr, er, F4, 0x50A28BE6u, 6,  7);
    ROUND(ar, br, cr, dr, er, F4, 0x50A28BE6u, 15, 8);
    ROUND(ar, br, cr, dr, er, F4, 0x50A28BE6u, 8,  11);
    ROUND(ar, br, cr, dr, er, F4, 0x50A28BE6u, 1,  14);
    ROUND(ar, br, cr, dr, er, F4, 0x50A28BE6u, 10, 14);
    ROUND(ar, br, cr, dr, er, F4, 0x50A28BE6u, 3,  12);
    ROUND(ar, br, cr, dr, er, F4, 0x50A28BE6u, 12, 6);

    /* Round 16..31: F3, K = 0x5C4DD124 */
    ROUND(ar, br, cr, dr, er, F3, 0x5C4DD124u, 6,  9);
    ROUND(ar, br, cr, dr, er, F3, 0x5C4DD124u, 11, 13);
    ROUND(ar, br, cr, dr, er, F3, 0x5C4DD124u, 3,  15);
    ROUND(ar, br, cr, dr, er, F3, 0x5C4DD124u, 7,  7);
    ROUND(ar, br, cr, dr, er, F3, 0x5C4DD124u, 0,  12);
    ROUND(ar, br, cr, dr, er, F3, 0x5C4DD124u, 13, 8);
    ROUND(ar, br, cr, dr, er, F3, 0x5C4DD124u, 5,  9);
    ROUND(ar, br, cr, dr, er, F3, 0x5C4DD124u, 10, 11);
    ROUND(ar, br, cr, dr, er, F3, 0x5C4DD124u, 14, 7);
    ROUND(ar, br, cr, dr, er, F3, 0x5C4DD124u, 15, 7);
    ROUND(ar, br, cr, dr, er, F3, 0x5C4DD124u, 8,  12);
    ROUND(ar, br, cr, dr, er, F3, 0x5C4DD124u, 12, 7);
    ROUND(ar, br, cr, dr, er, F3, 0x5C4DD124u, 4,  6);
    ROUND(ar, br, cr, dr, er, F3, 0x5C4DD124u, 9,  15);
    ROUND(ar, br, cr, dr, er, F3, 0x5C4DD124u, 1,  13);
    ROUND(ar, br, cr, dr, er, F3, 0x5C4DD124u, 2,  11);

    /* Round 32..47: F2, K = 0x6D703EF3 */
    ROUND(ar, br, cr, dr, er, F2, 0x6D703EF3u, 15, 9);
    ROUND(ar, br, cr, dr, er, F2, 0x6D703EF3u, 5,  7);
    ROUND(ar, br, cr, dr, er, F2, 0x6D703EF3u, 1,  15);
    ROUND(ar, br, cr, dr, er, F2, 0x6D703EF3u, 3,  11);
    ROUND(ar, br, cr, dr, er, F2, 0x6D703EF3u, 7,  8);
    ROUND(ar, br, cr, dr, er, F2, 0x6D703EF3u, 14, 6);
    ROUND(ar, br, cr, dr, er, F2, 0x6D703EF3u, 6,  6);
    ROUND(ar, br, cr, dr, er, F2, 0x6D703EF3u, 9,  14);
    ROUND(ar, br, cr, dr, er, F2, 0x6D703EF3u, 11, 12);
    ROUND(ar, br, cr, dr, er, F2, 0x6D703EF3u, 8,  13);
    ROUND(ar, br, cr, dr, er, F2, 0x6D703EF3u, 12, 5);
    ROUND(ar, br, cr, dr, er, F2, 0x6D703EF3u, 2,  14);
    ROUND(ar, br, cr, dr, er, F2, 0x6D703EF3u, 10, 13);
    ROUND(ar, br, cr, dr, er, F2, 0x6D703EF3u, 0,  13);
    ROUND(ar, br, cr, dr, er, F2, 0x6D703EF3u, 4,  7);
    ROUND(ar, br, cr, dr, er, F2, 0x6D703EF3u, 13, 5);

    /* Round 48..63: F1, K = 0x7A6D76E9 */
    ROUND(ar, br, cr, dr, er, F1, 0x7A6D76E9u, 8,  15);
    ROUND(ar, br, cr, dr, er, F1, 0x7A6D76E9u, 6,  5);
    ROUND(ar, br, cr, dr, er, F1, 0x7A6D76E9u, 4,  8);
    ROUND(ar, br, cr, dr, er, F1, 0x7A6D76E9u, 1,  11);
    ROUND(ar, br, cr, dr, er, F1, 0x7A6D76E9u, 3,  14);
    ROUND(ar, br, cr, dr, er, F1, 0x7A6D76E9u, 11, 14);
    ROUND(ar, br, cr, dr, er, F1, 0x7A6D76E9u, 15, 6);
    ROUND(ar, br, cr, dr, er, F1, 0x7A6D76E9u, 0,  14);
    ROUND(ar, br, cr, dr, er, F1, 0x7A6D76E9u, 5,  6);
    ROUND(ar, br, cr, dr, er, F1, 0x7A6D76E9u, 12, 9);
    ROUND(ar, br, cr, dr, er, F1, 0x7A6D76E9u, 2,  12);
    ROUND(ar, br, cr, dr, er, F1, 0x7A6D76E9u, 13, 9);
    ROUND(ar, br, cr, dr, er, F1, 0x7A6D76E9u, 9,  12);
    ROUND(ar, br, cr, dr, er, F1, 0x7A6D76E9u, 7,  5);
    ROUND(ar, br, cr, dr, er, F1, 0x7A6D76E9u, 10, 15);
    ROUND(ar, br, cr, dr, er, F1, 0x7A6D76E9u, 14, 8);

    /* Round 64..79: F0, K = 0 */
    ROUND(ar, br, cr, dr, er, F0, 0u, 12, 8);
    ROUND(ar, br, cr, dr, er, F0, 0u, 15, 5);
    ROUND(ar, br, cr, dr, er, F0, 0u, 10, 12);
    ROUND(ar, br, cr, dr, er, F0, 0u, 4,  9);
    ROUND(ar, br, cr, dr, er, F0, 0u, 1,  12);
    ROUND(ar, br, cr, dr, er, F0, 0u, 5,  5);
    ROUND(ar, br, cr, dr, er, F0, 0u, 8,  14);
    ROUND(ar, br, cr, dr, er, F0, 0u, 7,  6);
    ROUND(ar, br, cr, dr, er, F0, 0u, 6,  8);
    ROUND(ar, br, cr, dr, er, F0, 0u, 2,  13);
    ROUND(ar, br, cr, dr, er, F0, 0u, 13, 6);
    ROUND(ar, br, cr, dr, er, F0, 0u, 14, 5);
    ROUND(ar, br, cr, dr, er, F0, 0u, 0,  15);
    ROUND(ar, br, cr, dr, er, F0, 0u, 3,  13);
    ROUND(ar, br, cr, dr, er, F0, 0u, 9,  11);
    ROUND(ar, br, cr, dr, er, F0, 0u, 11, 11);

    /* Combine: H[i]' = IV[i+1] + cl + dr ; etc — see spec */
    __m256i h0 = ADD3(IV1, cl, dr);
    __m256i h1 = ADD3(IV2, dl, er);
    __m256i h2 = ADD3(IV3, el, ar);
    __m256i h3 = ADD3(IV4, al, br);
    __m256i h4 = ADD3(IV0, bl, cr);

    /* Transpose h0..h4 + 3 zero registers back to 8 outputs of 5 dwords each.
     * Simpler approach: extract each lane and write 20 bytes per output. */
    uint32_t h0v[8], h1v[8], h2v[8], h3v[8], h4v[8];
    _mm256_storeu_si256((__m256i*)h0v, h0);
    _mm256_storeu_si256((__m256i*)h1v, h1);
    _mm256_storeu_si256((__m256i*)h2v, h2);
    _mm256_storeu_si256((__m256i*)h3v, h3);
    _mm256_storeu_si256((__m256i*)h4v, h4);

    for (int i = 0; i < 8; i++) {
        uint8_t* o = out_8x20 + (size_t)i * 20;
        /* RIPEMD-160 output is little-endian per word. */
        memcpy(o + 0,  &h0v[i], 4);
        memcpy(o + 4,  &h1v[i], 4);
        memcpy(o + 8,  &h2v[i], 4);
        memcpy(o + 12, &h3v[i], 4);
        memcpy(o + 16, &h4v[i], 4);
    }
}

#else
#error "AVX2 is required to build the 8-way RIPEMD-160 hot path"
#endif

/* ===============================================================
 * SHA-NI single-block compress
 *
 * The Intel SHA Extensions provide _mm_sha256rnds2_epu32 (2 SHA-256 rounds
 * per call) and _mm_sha256msg1/2_epu32 (message schedule helpers). Operating
 * on the SHA-NI state layout — state0 = [F, E, B, A], state1 = [H, G, D, C]
 * (low-to-high lanes) — we run 64 rounds in 16 4-round groups.
 *
 * For our uncompressed pubkey input (65 bytes: 0x04 || x || y), this is a
 * 2-block compress: block 1 is bytes [0..64), block 2 is byte [64] followed
 * by 0x80 padding, zero pad, and the 64-bit big-endian length (520 bits).
 * =============================================================== */

#if defined(__SHA__)

static const uint32_t SGN_SHA256_IV[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
};

static inline void sha256_ni_load_state(__m128i *s0, __m128i *s1) {
    __m128i tmp;
    *s0 = _mm_loadu_si128((const __m128i*)&SGN_SHA256_IV[0]); /* [A B C D] */
    *s1 = _mm_loadu_si128((const __m128i*)&SGN_SHA256_IV[4]); /* [E F G H] */
    tmp = _mm_shuffle_epi32(*s0, 0xB1);                        /* [B A D C] */
    *s1 = _mm_shuffle_epi32(*s1, 0x1B);                        /* [H G F E] */
    *s0 = _mm_alignr_epi8(tmp, *s1, 8);                        /* [F E B A] */
    *s1 = _mm_blend_epi16(*s1, tmp, 0xF0);                     /* [H G D C] */
}

static inline void sha256_ni_store_state(__m128i s0, __m128i s1, uint8_t out[32]) {
    /* s0 = [F E B A], s1 = [H G D C] -> out = A B C D E F G H (big-endian per word) */
    __m128i tmp;
    tmp = _mm_shuffle_epi32(s0, 0x1B);                         /* [A B E F] */
    s1  = _mm_shuffle_epi32(s1, 0xB1);                         /* [C D G H] */
    s0  = _mm_blend_epi16(tmp, s1, 0xF0);                      /* [A B C D] */
    s1  = _mm_alignr_epi8(s1, tmp, 8);                         /* [E F G H] */
    const __m128i bswap = _mm_set_epi64x(
        0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);
    s0 = _mm_shuffle_epi8(s0, bswap);
    s1 = _mm_shuffle_epi8(s1, bswap);
    _mm_storeu_si128((__m128i*)(out + 0),  s0);
    _mm_storeu_si128((__m128i*)(out + 16), s1);
}

static void sha256_ni_compress(__m128i *state0, __m128i *state1, const uint8_t block[64]) {
    __m128i msg, tmp;
    __m128i msg0, msg1, msg2, msg3;
    __m128i s0_save = *state0, s1_save = *state1;
    const __m128i bswap = _mm_set_epi64x(
        0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);

    /* Rounds 0-3 */
    msg  = _mm_loadu_si128((const __m128i*)(block +  0));
    msg0 = _mm_shuffle_epi8(msg, bswap);
    msg  = _mm_add_epi32(msg0, _mm_set_epi64x(
        0xE9B5DBA5B5C0FBCFULL, 0x71374491428A2F98ULL));
    *state1 = _mm_sha256rnds2_epu32(*state1, *state0, msg);
    msg  = _mm_shuffle_epi32(msg, 0x0E);
    *state0 = _mm_sha256rnds2_epu32(*state0, *state1, msg);

    /* Rounds 4-7 */
    msg  = _mm_loadu_si128((const __m128i*)(block + 16));
    msg1 = _mm_shuffle_epi8(msg, bswap);
    msg  = _mm_add_epi32(msg1, _mm_set_epi64x(
        0xAB1C5ED5923F82A4ULL, 0x59F111F13956C25BULL));
    *state1 = _mm_sha256rnds2_epu32(*state1, *state0, msg);
    msg  = _mm_shuffle_epi32(msg, 0x0E);
    *state0 = _mm_sha256rnds2_epu32(*state0, *state1, msg);
    msg0 = _mm_sha256msg1_epu32(msg0, msg1);

    /* Rounds 8-11 */
    msg  = _mm_loadu_si128((const __m128i*)(block + 32));
    msg2 = _mm_shuffle_epi8(msg, bswap);
    msg  = _mm_add_epi32(msg2, _mm_set_epi64x(
        0x550C7DC3243185BEULL, 0x12835B01D807AA98ULL));
    *state1 = _mm_sha256rnds2_epu32(*state1, *state0, msg);
    msg  = _mm_shuffle_epi32(msg, 0x0E);
    *state0 = _mm_sha256rnds2_epu32(*state0, *state1, msg);
    msg1 = _mm_sha256msg1_epu32(msg1, msg2);

    /* Rounds 12-15 */
    msg  = _mm_loadu_si128((const __m128i*)(block + 48));
    msg3 = _mm_shuffle_epi8(msg, bswap);
    msg  = _mm_add_epi32(msg3, _mm_set_epi64x(
        0xC19BF1749BDC06A7ULL, 0x80DEB1FE72BE5D74ULL));
    *state1 = _mm_sha256rnds2_epu32(*state1, *state0, msg);
    tmp  = _mm_alignr_epi8(msg3, msg2, 4);
    msg0 = _mm_add_epi32(msg0, tmp);
    msg0 = _mm_sha256msg2_epu32(msg0, msg3);
    msg  = _mm_shuffle_epi32(msg, 0x0E);
    *state0 = _mm_sha256rnds2_epu32(*state0, *state1, msg);
    msg2 = _mm_sha256msg1_epu32(msg2, msg3);

    /* Rounds 16-19 */
    msg  = _mm_add_epi32(msg0, _mm_set_epi64x(
        0x240CA1CC0FC19DC6ULL, 0xEFBE4786E49B69C1ULL));
    *state1 = _mm_sha256rnds2_epu32(*state1, *state0, msg);
    tmp  = _mm_alignr_epi8(msg0, msg3, 4);
    msg1 = _mm_add_epi32(msg1, tmp);
    msg1 = _mm_sha256msg2_epu32(msg1, msg0);
    msg  = _mm_shuffle_epi32(msg, 0x0E);
    *state0 = _mm_sha256rnds2_epu32(*state0, *state1, msg);
    msg3 = _mm_sha256msg1_epu32(msg3, msg0);

    /* Rounds 20-23 */
    msg  = _mm_add_epi32(msg1, _mm_set_epi64x(
        0x76F988DA5CB0A9DCULL, 0x4A7484AA2DE92C6FULL));
    *state1 = _mm_sha256rnds2_epu32(*state1, *state0, msg);
    tmp  = _mm_alignr_epi8(msg1, msg0, 4);
    msg2 = _mm_add_epi32(msg2, tmp);
    msg2 = _mm_sha256msg2_epu32(msg2, msg1);
    msg  = _mm_shuffle_epi32(msg, 0x0E);
    *state0 = _mm_sha256rnds2_epu32(*state0, *state1, msg);
    msg0 = _mm_sha256msg1_epu32(msg0, msg1);

    /* Rounds 24-27 */
    msg  = _mm_add_epi32(msg2, _mm_set_epi64x(
        0xBF597FC7B00327C8ULL, 0xA831C66D983E5152ULL));
    *state1 = _mm_sha256rnds2_epu32(*state1, *state0, msg);
    tmp  = _mm_alignr_epi8(msg2, msg1, 4);
    msg3 = _mm_add_epi32(msg3, tmp);
    msg3 = _mm_sha256msg2_epu32(msg3, msg2);
    msg  = _mm_shuffle_epi32(msg, 0x0E);
    *state0 = _mm_sha256rnds2_epu32(*state0, *state1, msg);
    msg1 = _mm_sha256msg1_epu32(msg1, msg2);

    /* Rounds 28-31 */
    msg  = _mm_add_epi32(msg3, _mm_set_epi64x(
        0x1429296706CA6351ULL, 0xD5A79147C6E00BF3ULL));
    *state1 = _mm_sha256rnds2_epu32(*state1, *state0, msg);
    tmp  = _mm_alignr_epi8(msg3, msg2, 4);
    msg0 = _mm_add_epi32(msg0, tmp);
    msg0 = _mm_sha256msg2_epu32(msg0, msg3);
    msg  = _mm_shuffle_epi32(msg, 0x0E);
    *state0 = _mm_sha256rnds2_epu32(*state0, *state1, msg);
    msg2 = _mm_sha256msg1_epu32(msg2, msg3);

    /* Rounds 32-35 */
    msg  = _mm_add_epi32(msg0, _mm_set_epi64x(
        0x53380D134D2C6DFCULL, 0x2E1B213827B70A85ULL));
    *state1 = _mm_sha256rnds2_epu32(*state1, *state0, msg);
    tmp  = _mm_alignr_epi8(msg0, msg3, 4);
    msg1 = _mm_add_epi32(msg1, tmp);
    msg1 = _mm_sha256msg2_epu32(msg1, msg0);
    msg  = _mm_shuffle_epi32(msg, 0x0E);
    *state0 = _mm_sha256rnds2_epu32(*state0, *state1, msg);
    msg3 = _mm_sha256msg1_epu32(msg3, msg0);

    /* Rounds 36-39 */
    msg  = _mm_add_epi32(msg1, _mm_set_epi64x(
        0x92722C8581C2C92EULL, 0x766A0ABB650A7354ULL));
    *state1 = _mm_sha256rnds2_epu32(*state1, *state0, msg);
    tmp  = _mm_alignr_epi8(msg1, msg0, 4);
    msg2 = _mm_add_epi32(msg2, tmp);
    msg2 = _mm_sha256msg2_epu32(msg2, msg1);
    msg  = _mm_shuffle_epi32(msg, 0x0E);
    *state0 = _mm_sha256rnds2_epu32(*state0, *state1, msg);
    msg0 = _mm_sha256msg1_epu32(msg0, msg1);

    /* Rounds 40-43 */
    msg  = _mm_add_epi32(msg2, _mm_set_epi64x(
        0xC76C51A3C24B8B70ULL, 0xA81A664BA2BFE8A1ULL));
    *state1 = _mm_sha256rnds2_epu32(*state1, *state0, msg);
    tmp  = _mm_alignr_epi8(msg2, msg1, 4);
    msg3 = _mm_add_epi32(msg3, tmp);
    msg3 = _mm_sha256msg2_epu32(msg3, msg2);
    msg  = _mm_shuffle_epi32(msg, 0x0E);
    *state0 = _mm_sha256rnds2_epu32(*state0, *state1, msg);
    msg1 = _mm_sha256msg1_epu32(msg1, msg2);

    /* Rounds 44-47 */
    msg  = _mm_add_epi32(msg3, _mm_set_epi64x(
        0x106AA070F40E3585ULL, 0xD6990624D192E819ULL));
    *state1 = _mm_sha256rnds2_epu32(*state1, *state0, msg);
    tmp  = _mm_alignr_epi8(msg3, msg2, 4);
    msg0 = _mm_add_epi32(msg0, tmp);
    msg0 = _mm_sha256msg2_epu32(msg0, msg3);
    msg  = _mm_shuffle_epi32(msg, 0x0E);
    *state0 = _mm_sha256rnds2_epu32(*state0, *state1, msg);
    msg2 = _mm_sha256msg1_epu32(msg2, msg3);

    /* Rounds 48-51 */
    msg  = _mm_add_epi32(msg0, _mm_set_epi64x(
        0x34B0BCB52748774CULL, 0x1E376C0819A4C116ULL));
    *state1 = _mm_sha256rnds2_epu32(*state1, *state0, msg);
    tmp  = _mm_alignr_epi8(msg0, msg3, 4);
    msg1 = _mm_add_epi32(msg1, tmp);
    msg1 = _mm_sha256msg2_epu32(msg1, msg0);
    msg  = _mm_shuffle_epi32(msg, 0x0E);
    *state0 = _mm_sha256rnds2_epu32(*state0, *state1, msg);
    msg3 = _mm_sha256msg1_epu32(msg3, msg0);

    /* Rounds 52-55 */
    msg  = _mm_add_epi32(msg1, _mm_set_epi64x(
        0x682E6FF35B9CCA4FULL, 0x4ED8AA4A391C0CB3ULL));
    *state1 = _mm_sha256rnds2_epu32(*state1, *state0, msg);
    tmp  = _mm_alignr_epi8(msg1, msg0, 4);
    msg2 = _mm_add_epi32(msg2, tmp);
    msg2 = _mm_sha256msg2_epu32(msg2, msg1);
    msg  = _mm_shuffle_epi32(msg, 0x0E);
    *state0 = _mm_sha256rnds2_epu32(*state0, *state1, msg);

    /* Rounds 56-59 */
    msg  = _mm_add_epi32(msg2, _mm_set_epi64x(
        0x8CC7020884C87814ULL, 0x78A5636F748F82EEULL));
    *state1 = _mm_sha256rnds2_epu32(*state1, *state0, msg);
    tmp  = _mm_alignr_epi8(msg2, msg1, 4);
    msg3 = _mm_add_epi32(msg3, tmp);
    msg3 = _mm_sha256msg2_epu32(msg3, msg2);
    msg  = _mm_shuffle_epi32(msg, 0x0E);
    *state0 = _mm_sha256rnds2_epu32(*state0, *state1, msg);

    /* Rounds 60-63 */
    msg  = _mm_add_epi32(msg3, _mm_set_epi64x(
        0xC67178F2BEF9A3F7ULL, 0xA4506CEB90BEFFFAULL));
    *state1 = _mm_sha256rnds2_epu32(*state1, *state0, msg);
    msg  = _mm_shuffle_epi32(msg, 0x0E);
    *state0 = _mm_sha256rnds2_epu32(*state0, *state1, msg);

    *state0 = _mm_add_epi32(*state0, s0_save);
    *state1 = _mm_add_epi32(*state1, s1_save);
}

/* SHA-256 of an exactly-65-byte uncompressed pubkey: 0x04 || x || y. Block 1
 * is the first 64 bytes; block 2 is byte 64 + 0x80 padding + 64-bit BE length
 * (520 bits = 0x208). Output is 32 bytes big-endian. */
void sha256_pubkey_ni(uint8_t out[32], const uint8_t pub65[65]) {
    __m128i state0, state1;
    sha256_ni_load_state(&state0, &state1);

    sha256_ni_compress(&state0, &state1, pub65);

    uint8_t block2[64];
    memset(block2, 0, sizeof(block2));
    block2[0]  = pub65[64];
    block2[1]  = 0x80;
    /* length 520 bits in 64-bit big-endian -> bytes [56..64) */
    block2[62] = 0x02;
    block2[63] = 0x08;
    sha256_ni_compress(&state0, &state1, block2);

    sha256_ni_store_state(state0, state1, out);
}

#else
#error "SHA-NI is required to build the consolidated hot path"
#endif

/* ===============================================================
 * Target hashtable (open addressing, linear probe)
 *
 * Sized to a power of 2 with ~50% load factor on the caller's target count.
 * Initialized once via sgn_set_targets(); subsequent calls free and rebuild.
 * Lookup keys on the first 4 bytes of the h160 (cheap, well-distributed for
 * cryptographic hashes), then memcmps the full 20 bytes on probe match.
 * =============================================================== */

typedef struct {
    uint8_t hash160[20];
    uint8_t occupied;
} sgn_target_slot_t;

static sgn_target_slot_t* g_targets = NULL;
static uint32_t g_targets_mask = 0;

static inline uint32_t h160_first4_be(const uint8_t h[20]) {
    return ((uint32_t)h[0] << 24) | ((uint32_t)h[1] << 16)
         | ((uint32_t)h[2] <<  8) | ((uint32_t)h[3]);
}

void sgn_set_targets(const uint8_t* targets, uint32_t n_targets) {
    uint32_t size = 1;
    while (size < (uint64_t)n_targets * 2) size <<= 1;
    if (size < 16) size = 16;

    free(g_targets);
    g_targets = (sgn_target_slot_t*)calloc(size, sizeof(sgn_target_slot_t));
    g_targets_mask = size - 1;

    for (uint32_t i = 0; i < n_targets; i++) {
        const uint8_t* h = targets + (size_t)i * 20;
        uint32_t slot = h160_first4_be(h) & g_targets_mask;
        while (g_targets[slot].occupied) {
            slot = (slot + 1) & g_targets_mask;
        }
        memcpy(g_targets[slot].hash160, h, 20);
        g_targets[slot].occupied = 1;
    }
}

static inline int sgn_target_match(const uint8_t h160[20]) {
    if (!g_targets) return 0;
    uint32_t slot = h160_first4_be(h160) & g_targets_mask;
    while (g_targets[slot].occupied) {
        if (memcmp(g_targets[slot].hash160, h160, 20) == 0) return 1;
        slot = (slot + 1) & g_targets_mask;
    }
    return 0;
}

#include <stdlib.h> /* for free/calloc above; safe to include here too */

/* ===============================================================
 * Unified search batch entry point
 *
 * The whole hot path lives in this function:
 *   1. Use sgn_compute_affine_batch's algorithm internally to derive N
 *      affine x/y pairs from k0.
 *   2. For each chunk of 8 candidates: build 8 pub65 buffers inline,
 *      SHA-NI each, transpose into the 8-way RIPEMD input layout,
 *      run RIPEMD-160 → 8 hash160s, check each against the target table.
 *   3. Tail (remainder mod 8) handled with a small scalar fallback.
 *
 * Returns 1 on match (out_match populated), 0 on clean run.
 * out_match.batch_offset holds the offset i such that the matching priv key
 * is k0 + i (caller composes this in Rust via k256 Scalar arithmetic).
 * =============================================================== */

typedef struct {
    uint32_t found;
    uint32_t batch_offset;
    uint8_t  priv_key[32];   /* k0 + batch_offset, big-endian */
    uint8_t  hash160[20];
} sgn_match_t;

/* Helper to RIPEMD-160 8 packed inputs without going through the public
 * ripemd160_8way symbol (avoids per-chunk function-call overhead in this
 * hot loop; the macro logic is identical). Reuses the same ROUND macro
 * scope, which is in this file. */
static inline void sgn_ripemd_8way_inline(
    const __m256i sha_packed[8], /* 8 transposed 32-bit words */
    uint8_t out_8x20[8 * 20]
) {
    __m256i X[16];
    /* Caller has already transposed: sha_packed[i] is word i across 8 lanes. */
    for (int i = 0; i < 8; i++) X[i] = sha_packed[i];
    X[8]  = _mm256_set1_epi32(0x00000080);
    X[9]  = _mm256_setzero_si256();
    X[10] = _mm256_setzero_si256();
    X[11] = _mm256_setzero_si256();
    X[12] = _mm256_setzero_si256();
    X[13] = _mm256_setzero_si256();
    X[14] = _mm256_set1_epi32(256);
    X[15] = _mm256_setzero_si256();

    const __m256i IV0 = _mm256_set1_epi32((int)0x67452301);
    const __m256i IV1 = _mm256_set1_epi32((int)0xefcdab89);
    const __m256i IV2 = _mm256_set1_epi32((int)0x98badcfe);
    const __m256i IV3 = _mm256_set1_epi32((int)0x10325476);
    const __m256i IV4 = _mm256_set1_epi32((int)0xc3d2e1f0);

    __m256i al = IV0, bl = IV1, cl = IV2, dl = IV3, el = IV4;
    __m256i ar = IV0, br = IV1, cr = IV2, dr = IV3, er = IV4;

    /* Reuse the ROUND macro from the 8-way RIPEMD section above. */
    /* LEFT LINE */
    ROUND(al, bl, cl, dl, el, F0, 0u, 0,  11);
    ROUND(al, bl, cl, dl, el, F0, 0u, 1,  14);
    ROUND(al, bl, cl, dl, el, F0, 0u, 2,  15);
    ROUND(al, bl, cl, dl, el, F0, 0u, 3,  12);
    ROUND(al, bl, cl, dl, el, F0, 0u, 4,  5);
    ROUND(al, bl, cl, dl, el, F0, 0u, 5,  8);
    ROUND(al, bl, cl, dl, el, F0, 0u, 6,  7);
    ROUND(al, bl, cl, dl, el, F0, 0u, 7,  9);
    ROUND(al, bl, cl, dl, el, F0, 0u, 8,  11);
    ROUND(al, bl, cl, dl, el, F0, 0u, 9,  13);
    ROUND(al, bl, cl, dl, el, F0, 0u, 10, 14);
    ROUND(al, bl, cl, dl, el, F0, 0u, 11, 15);
    ROUND(al, bl, cl, dl, el, F0, 0u, 12, 6);
    ROUND(al, bl, cl, dl, el, F0, 0u, 13, 7);
    ROUND(al, bl, cl, dl, el, F0, 0u, 14, 9);
    ROUND(al, bl, cl, dl, el, F0, 0u, 15, 8);
    ROUND(al, bl, cl, dl, el, F1, 0x5A827999u, 7,  7);
    ROUND(al, bl, cl, dl, el, F1, 0x5A827999u, 4,  6);
    ROUND(al, bl, cl, dl, el, F1, 0x5A827999u, 13, 8);
    ROUND(al, bl, cl, dl, el, F1, 0x5A827999u, 1,  13);
    ROUND(al, bl, cl, dl, el, F1, 0x5A827999u, 10, 11);
    ROUND(al, bl, cl, dl, el, F1, 0x5A827999u, 6,  9);
    ROUND(al, bl, cl, dl, el, F1, 0x5A827999u, 15, 7);
    ROUND(al, bl, cl, dl, el, F1, 0x5A827999u, 3,  15);
    ROUND(al, bl, cl, dl, el, F1, 0x5A827999u, 12, 7);
    ROUND(al, bl, cl, dl, el, F1, 0x5A827999u, 0,  12);
    ROUND(al, bl, cl, dl, el, F1, 0x5A827999u, 9,  15);
    ROUND(al, bl, cl, dl, el, F1, 0x5A827999u, 5,  9);
    ROUND(al, bl, cl, dl, el, F1, 0x5A827999u, 2,  11);
    ROUND(al, bl, cl, dl, el, F1, 0x5A827999u, 14, 7);
    ROUND(al, bl, cl, dl, el, F1, 0x5A827999u, 11, 13);
    ROUND(al, bl, cl, dl, el, F1, 0x5A827999u, 8,  12);
    ROUND(al, bl, cl, dl, el, F2, 0x6ED9EBA1u, 3,  11);
    ROUND(al, bl, cl, dl, el, F2, 0x6ED9EBA1u, 10, 13);
    ROUND(al, bl, cl, dl, el, F2, 0x6ED9EBA1u, 14, 6);
    ROUND(al, bl, cl, dl, el, F2, 0x6ED9EBA1u, 4,  7);
    ROUND(al, bl, cl, dl, el, F2, 0x6ED9EBA1u, 9,  14);
    ROUND(al, bl, cl, dl, el, F2, 0x6ED9EBA1u, 15, 9);
    ROUND(al, bl, cl, dl, el, F2, 0x6ED9EBA1u, 8,  13);
    ROUND(al, bl, cl, dl, el, F2, 0x6ED9EBA1u, 1,  15);
    ROUND(al, bl, cl, dl, el, F2, 0x6ED9EBA1u, 2,  14);
    ROUND(al, bl, cl, dl, el, F2, 0x6ED9EBA1u, 7,  8);
    ROUND(al, bl, cl, dl, el, F2, 0x6ED9EBA1u, 0,  13);
    ROUND(al, bl, cl, dl, el, F2, 0x6ED9EBA1u, 6,  6);
    ROUND(al, bl, cl, dl, el, F2, 0x6ED9EBA1u, 13, 5);
    ROUND(al, bl, cl, dl, el, F2, 0x6ED9EBA1u, 11, 12);
    ROUND(al, bl, cl, dl, el, F2, 0x6ED9EBA1u, 5,  7);
    ROUND(al, bl, cl, dl, el, F2, 0x6ED9EBA1u, 12, 5);
    ROUND(al, bl, cl, dl, el, F3, 0x8F1BBCDCu, 1,  11);
    ROUND(al, bl, cl, dl, el, F3, 0x8F1BBCDCu, 9,  12);
    ROUND(al, bl, cl, dl, el, F3, 0x8F1BBCDCu, 11, 14);
    ROUND(al, bl, cl, dl, el, F3, 0x8F1BBCDCu, 10, 15);
    ROUND(al, bl, cl, dl, el, F3, 0x8F1BBCDCu, 0,  14);
    ROUND(al, bl, cl, dl, el, F3, 0x8F1BBCDCu, 8,  15);
    ROUND(al, bl, cl, dl, el, F3, 0x8F1BBCDCu, 12, 9);
    ROUND(al, bl, cl, dl, el, F3, 0x8F1BBCDCu, 4,  8);
    ROUND(al, bl, cl, dl, el, F3, 0x8F1BBCDCu, 13, 9);
    ROUND(al, bl, cl, dl, el, F3, 0x8F1BBCDCu, 3,  14);
    ROUND(al, bl, cl, dl, el, F3, 0x8F1BBCDCu, 7,  5);
    ROUND(al, bl, cl, dl, el, F3, 0x8F1BBCDCu, 15, 6);
    ROUND(al, bl, cl, dl, el, F3, 0x8F1BBCDCu, 14, 8);
    ROUND(al, bl, cl, dl, el, F3, 0x8F1BBCDCu, 5,  6);
    ROUND(al, bl, cl, dl, el, F3, 0x8F1BBCDCu, 6,  5);
    ROUND(al, bl, cl, dl, el, F3, 0x8F1BBCDCu, 2,  12);
    ROUND(al, bl, cl, dl, el, F4, 0xA953FD4Eu, 4,  9);
    ROUND(al, bl, cl, dl, el, F4, 0xA953FD4Eu, 0,  15);
    ROUND(al, bl, cl, dl, el, F4, 0xA953FD4Eu, 5,  5);
    ROUND(al, bl, cl, dl, el, F4, 0xA953FD4Eu, 9,  11);
    ROUND(al, bl, cl, dl, el, F4, 0xA953FD4Eu, 7,  6);
    ROUND(al, bl, cl, dl, el, F4, 0xA953FD4Eu, 12, 8);
    ROUND(al, bl, cl, dl, el, F4, 0xA953FD4Eu, 2,  13);
    ROUND(al, bl, cl, dl, el, F4, 0xA953FD4Eu, 10, 12);
    ROUND(al, bl, cl, dl, el, F4, 0xA953FD4Eu, 14, 5);
    ROUND(al, bl, cl, dl, el, F4, 0xA953FD4Eu, 1,  12);
    ROUND(al, bl, cl, dl, el, F4, 0xA953FD4Eu, 3,  13);
    ROUND(al, bl, cl, dl, el, F4, 0xA953FD4Eu, 8,  14);
    ROUND(al, bl, cl, dl, el, F4, 0xA953FD4Eu, 11, 11);
    ROUND(al, bl, cl, dl, el, F4, 0xA953FD4Eu, 6,  8);
    ROUND(al, bl, cl, dl, el, F4, 0xA953FD4Eu, 15, 5);
    ROUND(al, bl, cl, dl, el, F4, 0xA953FD4Eu, 13, 6);

    /* RIGHT LINE */
    ROUND(ar, br, cr, dr, er, F4, 0x50A28BE6u, 5,  8);
    ROUND(ar, br, cr, dr, er, F4, 0x50A28BE6u, 14, 9);
    ROUND(ar, br, cr, dr, er, F4, 0x50A28BE6u, 7,  9);
    ROUND(ar, br, cr, dr, er, F4, 0x50A28BE6u, 0,  11);
    ROUND(ar, br, cr, dr, er, F4, 0x50A28BE6u, 9,  13);
    ROUND(ar, br, cr, dr, er, F4, 0x50A28BE6u, 2,  15);
    ROUND(ar, br, cr, dr, er, F4, 0x50A28BE6u, 11, 15);
    ROUND(ar, br, cr, dr, er, F4, 0x50A28BE6u, 4,  5);
    ROUND(ar, br, cr, dr, er, F4, 0x50A28BE6u, 13, 7);
    ROUND(ar, br, cr, dr, er, F4, 0x50A28BE6u, 6,  7);
    ROUND(ar, br, cr, dr, er, F4, 0x50A28BE6u, 15, 8);
    ROUND(ar, br, cr, dr, er, F4, 0x50A28BE6u, 8,  11);
    ROUND(ar, br, cr, dr, er, F4, 0x50A28BE6u, 1,  14);
    ROUND(ar, br, cr, dr, er, F4, 0x50A28BE6u, 10, 14);
    ROUND(ar, br, cr, dr, er, F4, 0x50A28BE6u, 3,  12);
    ROUND(ar, br, cr, dr, er, F4, 0x50A28BE6u, 12, 6);
    ROUND(ar, br, cr, dr, er, F3, 0x5C4DD124u, 6,  9);
    ROUND(ar, br, cr, dr, er, F3, 0x5C4DD124u, 11, 13);
    ROUND(ar, br, cr, dr, er, F3, 0x5C4DD124u, 3,  15);
    ROUND(ar, br, cr, dr, er, F3, 0x5C4DD124u, 7,  7);
    ROUND(ar, br, cr, dr, er, F3, 0x5C4DD124u, 0,  12);
    ROUND(ar, br, cr, dr, er, F3, 0x5C4DD124u, 13, 8);
    ROUND(ar, br, cr, dr, er, F3, 0x5C4DD124u, 5,  9);
    ROUND(ar, br, cr, dr, er, F3, 0x5C4DD124u, 10, 11);
    ROUND(ar, br, cr, dr, er, F3, 0x5C4DD124u, 14, 7);
    ROUND(ar, br, cr, dr, er, F3, 0x5C4DD124u, 15, 7);
    ROUND(ar, br, cr, dr, er, F3, 0x5C4DD124u, 8,  12);
    ROUND(ar, br, cr, dr, er, F3, 0x5C4DD124u, 12, 7);
    ROUND(ar, br, cr, dr, er, F3, 0x5C4DD124u, 4,  6);
    ROUND(ar, br, cr, dr, er, F3, 0x5C4DD124u, 9,  15);
    ROUND(ar, br, cr, dr, er, F3, 0x5C4DD124u, 1,  13);
    ROUND(ar, br, cr, dr, er, F3, 0x5C4DD124u, 2,  11);
    ROUND(ar, br, cr, dr, er, F2, 0x6D703EF3u, 15, 9);
    ROUND(ar, br, cr, dr, er, F2, 0x6D703EF3u, 5,  7);
    ROUND(ar, br, cr, dr, er, F2, 0x6D703EF3u, 1,  15);
    ROUND(ar, br, cr, dr, er, F2, 0x6D703EF3u, 3,  11);
    ROUND(ar, br, cr, dr, er, F2, 0x6D703EF3u, 7,  8);
    ROUND(ar, br, cr, dr, er, F2, 0x6D703EF3u, 14, 6);
    ROUND(ar, br, cr, dr, er, F2, 0x6D703EF3u, 6,  6);
    ROUND(ar, br, cr, dr, er, F2, 0x6D703EF3u, 9,  14);
    ROUND(ar, br, cr, dr, er, F2, 0x6D703EF3u, 11, 12);
    ROUND(ar, br, cr, dr, er, F2, 0x6D703EF3u, 8,  13);
    ROUND(ar, br, cr, dr, er, F2, 0x6D703EF3u, 12, 5);
    ROUND(ar, br, cr, dr, er, F2, 0x6D703EF3u, 2,  14);
    ROUND(ar, br, cr, dr, er, F2, 0x6D703EF3u, 10, 13);
    ROUND(ar, br, cr, dr, er, F2, 0x6D703EF3u, 0,  13);
    ROUND(ar, br, cr, dr, er, F2, 0x6D703EF3u, 4,  7);
    ROUND(ar, br, cr, dr, er, F2, 0x6D703EF3u, 13, 5);
    ROUND(ar, br, cr, dr, er, F1, 0x7A6D76E9u, 8,  15);
    ROUND(ar, br, cr, dr, er, F1, 0x7A6D76E9u, 6,  5);
    ROUND(ar, br, cr, dr, er, F1, 0x7A6D76E9u, 4,  8);
    ROUND(ar, br, cr, dr, er, F1, 0x7A6D76E9u, 1,  11);
    ROUND(ar, br, cr, dr, er, F1, 0x7A6D76E9u, 3,  14);
    ROUND(ar, br, cr, dr, er, F1, 0x7A6D76E9u, 11, 14);
    ROUND(ar, br, cr, dr, er, F1, 0x7A6D76E9u, 15, 6);
    ROUND(ar, br, cr, dr, er, F1, 0x7A6D76E9u, 0,  14);
    ROUND(ar, br, cr, dr, er, F1, 0x7A6D76E9u, 5,  6);
    ROUND(ar, br, cr, dr, er, F1, 0x7A6D76E9u, 12, 9);
    ROUND(ar, br, cr, dr, er, F1, 0x7A6D76E9u, 2,  12);
    ROUND(ar, br, cr, dr, er, F1, 0x7A6D76E9u, 13, 9);
    ROUND(ar, br, cr, dr, er, F1, 0x7A6D76E9u, 9,  12);
    ROUND(ar, br, cr, dr, er, F1, 0x7A6D76E9u, 7,  5);
    ROUND(ar, br, cr, dr, er, F1, 0x7A6D76E9u, 10, 15);
    ROUND(ar, br, cr, dr, er, F1, 0x7A6D76E9u, 14, 8);
    ROUND(ar, br, cr, dr, er, F0, 0u, 12, 8);
    ROUND(ar, br, cr, dr, er, F0, 0u, 15, 5);
    ROUND(ar, br, cr, dr, er, F0, 0u, 10, 12);
    ROUND(ar, br, cr, dr, er, F0, 0u, 4,  9);
    ROUND(ar, br, cr, dr, er, F0, 0u, 1,  12);
    ROUND(ar, br, cr, dr, er, F0, 0u, 5,  5);
    ROUND(ar, br, cr, dr, er, F0, 0u, 8,  14);
    ROUND(ar, br, cr, dr, er, F0, 0u, 7,  6);
    ROUND(ar, br, cr, dr, er, F0, 0u, 6,  8);
    ROUND(ar, br, cr, dr, er, F0, 0u, 2,  13);
    ROUND(ar, br, cr, dr, er, F0, 0u, 13, 6);
    ROUND(ar, br, cr, dr, er, F0, 0u, 14, 5);
    ROUND(ar, br, cr, dr, er, F0, 0u, 0,  15);
    ROUND(ar, br, cr, dr, er, F0, 0u, 3,  13);
    ROUND(ar, br, cr, dr, er, F0, 0u, 9,  11);
    ROUND(ar, br, cr, dr, er, F0, 0u, 11, 11);

    __m256i h0 = ADD3(IV1, cl, dr);
    __m256i h1 = ADD3(IV2, dl, er);
    __m256i h2 = ADD3(IV3, el, ar);
    __m256i h3 = ADD3(IV4, al, br);
    __m256i h4 = ADD3(IV0, bl, cr);

    uint32_t h0v[8], h1v[8], h2v[8], h3v[8], h4v[8];
    _mm256_storeu_si256((__m256i*)h0v, h0);
    _mm256_storeu_si256((__m256i*)h1v, h1);
    _mm256_storeu_si256((__m256i*)h2v, h2);
    _mm256_storeu_si256((__m256i*)h3v, h3);
    _mm256_storeu_si256((__m256i*)h4v, h4);

    for (int i = 0; i < 8; i++) {
        uint8_t* o = out_8x20 + (size_t)i * 20;
        memcpy(o + 0,  &h0v[i], 4);
        memcpy(o + 4,  &h1v[i], 4);
        memcpy(o + 8,  &h2v[i], 4);
        memcpy(o + 12, &h3v[i], 4);
        memcpy(o + 16, &h4v[i], 4);
    }
}

int sgn_search_batch(
    const uint8_t* k0_bytes,
    uint32_t n,
    sgn_match_t* out_match
) {
    out_match->found = 0;
    out_match->batch_offset = 0;
    memset(out_match->priv_key, 0, 32);
    memset(out_match->hash160, 0, 20);

    if (n == 0 || n > SGN_MAX_BATCH) return 0;

    /* EC math: reuse the same logic as sgn_compute_affine_batch but skip the
     * outer xy_buf serialization. We hold affine x/y in field-element form
     * across the loop and serialize only what we need into the SHA-NI input. */

    if (!g_gen_state.built) {
        secp256k1_ecmult_gen_context_build(&g_gen_state.ctx);
        g_gen_state.built = 1;
    }

    secp256k1_scalar k0;
    int overflow = 0;
    secp256k1_scalar_set_b32(&k0, k0_bytes, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&k0)) return 0;

    secp256k1_ecmult_gen(&g_gen_state.ctx, &g_chain[0], &k0);
    for (uint32_t i = 1; i < n; i++) {
        secp256k1_gej_add_ge_var(&g_chain[i], &g_chain[i - 1], &secp256k1_ge_const_g, NULL);
    }

    g_zacc[0] = g_chain[0].z;
    for (uint32_t i = 1; i < n; i++) {
        secp256k1_fe_mul(&g_zacc[i], &g_zacc[i - 1], &g_chain[i].z);
    }
    secp256k1_fe acc_inv;
    secp256k1_fe_inv(&acc_inv, &g_zacc[n - 1]);
    for (uint32_t i = n - 1; i > 0; i--) {
        secp256k1_fe_mul(&g_zinv[i], &acc_inv, &g_zacc[i - 1]);
        secp256k1_fe_mul(&acc_inv, &acc_inv, &g_chain[i].z);
    }
    g_zinv[0] = acc_inv;

    /* Process candidates in groups of 8: SHA-NI each, transpose to RIPEMD
     * input layout, run 8-way RIPEMD inline, target lookup. */
    uint8_t pub65[65];
    pub65[0] = 0x04;

    uint32_t i = 0;
    for (; i + 8 <= n; i += 8) {
        /* Compute 8 affine points + their SHA-256 outputs. */
        __m128i sha_words[8][2]; /* unused, we go straight to packed __m256i */
        (void)sha_words;
        uint32_t sha_out[8][8]; /* [lane][word] */

        for (int j = 0; j < 8; j++) {
            uint32_t idx = i + (uint32_t)j;
            secp256k1_fe z2, z3, x, y;
            secp256k1_fe_sqr(&z2, &g_zinv[idx]);
            secp256k1_fe_mul(&z3, &z2, &g_zinv[idx]);
            secp256k1_fe_mul(&x, &g_chain[idx].x, &z2);
            secp256k1_fe_mul(&y, &g_chain[idx].y, &z3);
            secp256k1_fe_normalize_var(&x);
            secp256k1_fe_normalize_var(&y);
            secp256k1_fe_get_b32(pub65 + 1,  &x);
            secp256k1_fe_get_b32(pub65 + 33, &y);

            uint8_t sha_bytes[32];
            sha256_pubkey_ni(sha_bytes, pub65);

            /* Load SHA bytes as 8 little-endian uint32s — RIPEMD-160 reads
             * its message words little-endian, which matches x86's natural
             * 32-bit load order. */
            for (int w = 0; w < 8; w++) {
                sha_out[j][w] =
                    ((uint32_t)sha_bytes[w * 4 + 0])
                  | ((uint32_t)sha_bytes[w * 4 + 1] << 8)
                  | ((uint32_t)sha_bytes[w * 4 + 2] << 16)
                  | ((uint32_t)sha_bytes[w * 4 + 3] << 24);
            }
        }

        /* Transpose the 8x8 word matrix into __m256i so word w holds the
         * w-th word from each of the 8 lanes (the layout RIPEMD expects). */
        __m256i a[8];
        for (int j = 0; j < 8; j++) {
            a[j] = _mm256_loadu_si256((const __m256i*)sha_out[j]);
        }
        __m256i X8[8];
        {
            __m256i s0 = _mm256_unpacklo_epi32(a[0], a[1]);
            __m256i s1 = _mm256_unpackhi_epi32(a[0], a[1]);
            __m256i s2 = _mm256_unpacklo_epi32(a[2], a[3]);
            __m256i s3 = _mm256_unpackhi_epi32(a[2], a[3]);
            __m256i s4 = _mm256_unpacklo_epi32(a[4], a[5]);
            __m256i s5 = _mm256_unpackhi_epi32(a[4], a[5]);
            __m256i s6 = _mm256_unpacklo_epi32(a[6], a[7]);
            __m256i s7 = _mm256_unpackhi_epi32(a[6], a[7]);
            __m256i u0 = _mm256_unpacklo_epi64(s0, s2);
            __m256i u1 = _mm256_unpackhi_epi64(s0, s2);
            __m256i u2 = _mm256_unpacklo_epi64(s1, s3);
            __m256i u3 = _mm256_unpackhi_epi64(s1, s3);
            __m256i u4 = _mm256_unpacklo_epi64(s4, s6);
            __m256i u5 = _mm256_unpackhi_epi64(s4, s6);
            __m256i u6 = _mm256_unpacklo_epi64(s5, s7);
            __m256i u7 = _mm256_unpackhi_epi64(s5, s7);
            X8[0] = _mm256_permute2x128_si256(u0, u4, 0x20);
            X8[1] = _mm256_permute2x128_si256(u1, u5, 0x20);
            X8[2] = _mm256_permute2x128_si256(u2, u6, 0x20);
            X8[3] = _mm256_permute2x128_si256(u3, u7, 0x20);
            X8[4] = _mm256_permute2x128_si256(u0, u4, 0x31);
            X8[5] = _mm256_permute2x128_si256(u1, u5, 0x31);
            X8[6] = _mm256_permute2x128_si256(u2, u6, 0x31);
            X8[7] = _mm256_permute2x128_si256(u3, u7, 0x31);
        }

        uint8_t h160_pack[8 * 20];
        sgn_ripemd_8way_inline(X8, h160_pack);

        for (int j = 0; j < 8; j++) {
            const uint8_t* h = h160_pack + (size_t)j * 20;
            if (sgn_target_match(h)) {
                out_match->found = 1;
                out_match->batch_offset = i + (uint32_t)j;
                memcpy(out_match->hash160, h, 20);
                /* Compose priv = k0 + offset using libsecp scalar arithmetic. */
                secp256k1_scalar offset_scalar;
                secp256k1_scalar_set_int(&offset_scalar, out_match->batch_offset);
                secp256k1_scalar priv;
                secp256k1_scalar_add(&priv, &k0, &offset_scalar);
                secp256k1_scalar_get_b32(out_match->priv_key, &priv);
                return 1;
            }
        }
    }

    /* Tail: any remainder mod 8. Falls back to scalar Ripemd would need a
     * dependency we don't have here — but n is always a power of 2 in
     * practice (production uses 8192), so this path is unused. We still
     * handle it defensively by computing one-at-a-time using the 8-way
     * ripemd with the candidate replicated 8 times (hash result the same
     * across all lanes). */
    for (; i < n; i++) {
        secp256k1_fe z2, z3, x, y;
        secp256k1_fe_sqr(&z2, &g_zinv[i]);
        secp256k1_fe_mul(&z3, &z2, &g_zinv[i]);
        secp256k1_fe_mul(&x, &g_chain[i].x, &z2);
        secp256k1_fe_mul(&y, &g_chain[i].y, &z3);
        secp256k1_fe_normalize_var(&x);
        secp256k1_fe_normalize_var(&y);
        secp256k1_fe_get_b32(pub65 + 1,  &x);
        secp256k1_fe_get_b32(pub65 + 33, &y);

        uint8_t sha_bytes[32];
        sha256_pubkey_ni(sha_bytes, pub65);

        uint8_t packed_in[8 * 32];
        for (int j = 0; j < 8; j++) memcpy(packed_in + j * 32, sha_bytes, 32);
        uint8_t packed_out[8 * 20];
        ripemd160_8way(packed_in, packed_out);

        if (sgn_target_match(packed_out)) {
            out_match->found = 1;
            out_match->batch_offset = i;
            memcpy(out_match->hash160, packed_out, 20);
            secp256k1_scalar offset_scalar;
            secp256k1_scalar_set_int(&offset_scalar, i);
            secp256k1_scalar priv;
            secp256k1_scalar_add(&priv, &k0, &offset_scalar);
            secp256k1_scalar_get_b32(out_match->priv_key, &priv);
            return 1;
        }
    }

    return 0;
}
