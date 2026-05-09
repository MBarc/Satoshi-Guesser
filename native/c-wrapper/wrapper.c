/*
 * c-wrapper for Satoshi Guesser native addon.
 *
 * Exposes:
 *   - sgn_wrapper_sentinel():        build-pipeline check (returns 0xCAFEBABE)
 *   - sgn_compute_affine_batch():    libsecp256k1-internal scalar mult +
 *                                    Jacobian walk + Montgomery batch invert.
 *                                    Writes N × 64 bytes (32 byte BE x ||
 *                                    32 byte BE y) to caller's buffer.
 *   - ripemd160_8way():              8-way AVX2 RIPEMD-160. 8 independent
 *                                    32-byte inputs -> 8 × 20-byte outputs.
 *
 * Hybrid strategy: hashing stays in Rust (sha2's SHA-NI path + this file's
 * 8-way RIPEMD-160 via FFI). Only the EC math goes through libsecp's hand-
 * tuned field arithmetic, which beats k256's pure Rust by ~30% on Jacobian
 * additions. A previous attempt at full-C hashing regressed because
 * libsecp's portable SHA-256 has no SHA-NI; this design avoids that trap.
 *
 * RIPEMD-160 spec:
 *   https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
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
