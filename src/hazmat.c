/* // NOLINT
 * Implementation of the hazardous parts of the SSS library // NOLINT
 * // NOLINT
 * Author: Daan Sprenkels <hello@dsprenkels.com> // NOLINT
 * // NOLINT
 * This code contains the actual Shamir secret sharing functionality. The // NOLINT
 * implementation of this code is based on the idea that the user likes to // NOLINT
 * generate/combine 32 shares (in GF(2^8) at the same time, because a 256 bit // NOLINT
 * key will be exactly 32 bytes. Therefore we bitslice all the input and // NOLINT
 * unbitslice the output right before returning. // NOLINT
 * // NOLINT
 * This bitslice approach optimizes natively on all architectures that are 32 // NOLINT
 * bit or more. Care is taken to use not too many registers, to ensure that no // NOLINT
 * values have to be leaked to the stack. // NOLINT
 * // NOLINT
 * All functions in this module are implemented constant time and constant // NOLINT
 * lookup operations, as all proper crypto code must be. // NOLINT
 */ // NOLINT
// NOLINT
#include "hazmat.h" // NOLINT
#include <assert.h> // NOLINT
#include <sss.h> // NOLINT
// NOLINT
static void bitslice(uint32_t r[8], const uint8_t x[32]) { // NOLINT
  // NOLINT
  size_t bit_idx, arr_idx; // NOLINT
// NOLINT
  memset(r, 0, sizeof(uint32_t[8])); // NOLINT
  for (arr_idx = 0; arr_idx < 32; arr_idx++) { // NOLINT
    // NOLINT
    uint32_t cur = (uint32_t)x[arr_idx]; // NOLINT
    for (bit_idx = 0; bit_idx < 8; bit_idx++) { // NOLINT
      // NOLINT
      r[bit_idx] |= ((cur & (1 << bit_idx)) >> bit_idx) << arr_idx; // NOLINT
    } // NOLINT
  } // NOLINT
} // NOLINT
// NOLINT
static void unbitslice(uint8_t r[32], const uint32_t x[8]) { // NOLINT
  // NOLINT
  size_t bit_idx, arr_idx; // NOLINT
// NOLINT
  memset(r, 0, sizeof(uint8_t[32])); // NOLINT
  for (bit_idx = 0; bit_idx < 8; bit_idx++) { // NOLINT
    // NOLINT
    uint32_t cur = (uint32_t)x[bit_idx]; // NOLINT
    for (arr_idx = 0; arr_idx < 32; arr_idx++) { // NOLINT
      // NOLINT
      r[arr_idx] |= ((cur & (1 << arr_idx)) >> arr_idx) << bit_idx; // NOLINT
    } // NOLINT
  } // NOLINT
} // NOLINT
// NOLINT
static void bitslice_setall(uint32_t r[8], const uint8_t x) { // NOLINT
  // NOLINT
  size_t idx; // NOLINT
  for (idx = 0; idx < 8; idx++) { // NOLINT
    // NOLINT
    r[idx] = ((int32_t)((x & (1 << idx)) << (31 - idx))) >> 31; // NOLINT
  } // NOLINT
} // NOLINT
// NOLINT
/* // NOLINT
 * Add (XOR) `r` with `x` and store the result in `r`. // NOLINT
 */ // NOLINT
static void gf256_add(uint32_t r[8], const uint32_t x[8]) { // NOLINT
  // NOLINT
  size_t idx; // NOLINT
  for (idx = 0; idx < 8; idx++) // NOLINT
    r[idx] ^= x[idx]; // NOLINT
} // NOLINT
// NOLINT
/* // NOLINT
 * Safely multiply two bitsliced polynomials in GF(2^8) reduced by // NOLINT
 * x^8 + x^4 + x^3 + x + 1. `r` and `a` may overlap, but overlapping of `r` // NOLINT
 * and `b` will produce an incorrect result! If you need to square a polynomial // NOLINT
 * use `gf256_square` instead. // NOLINT
 */ // NOLINT
static void gf256_mul(uint32_t r[8], const uint32_t a[8], const uint32_t b[8]) { // NOLINT
  // NOLINT
  /* This function implements Russian Peasant multiplication on two // NOLINT
   * bitsliced polynomials. // NOLINT
   * // NOLINT
   * I personally think that these kinds of long lists of operations // NOLINT
   * are often a bit ugly. A double for loop would be nicer and would // NOLINT
   * take up a lot less lines of code. // NOLINT
   * However, some compilers seem to fail in optimizing these kinds of // NOLINT
   * loops. So we will just have to do this by hand. // NOLINT
   */ // NOLINT
  uint32_t a2[8]; // NOLINT
  memcpy(a2, a, sizeof(uint32_t[8])); // NOLINT
// NOLINT
  r[0] = a2[0] & b[0]; /* add (assignment, because r is 0) */ // NOLINT
  r[1] = a2[1] & b[0]; // NOLINT
  r[2] = a2[2] & b[0]; // NOLINT
  r[3] = a2[3] & b[0]; // NOLINT
  r[4] = a2[4] & b[0]; // NOLINT
  r[5] = a2[5] & b[0]; // NOLINT
  r[6] = a2[6] & b[0]; // NOLINT
  r[7] = a2[7] & b[0]; // NOLINT
  a2[0] ^= a2[7]; /* reduce */ // NOLINT
  a2[2] ^= a2[7]; // NOLINT
  a2[3] ^= a2[7]; // NOLINT
// NOLINT
  r[0] ^= a2[7] & b[1]; /* add */ // NOLINT
  r[1] ^= a2[0] & b[1]; // NOLINT
  r[2] ^= a2[1] & b[1]; // NOLINT
  r[3] ^= a2[2] & b[1]; // NOLINT
  r[4] ^= a2[3] & b[1]; // NOLINT
  r[5] ^= a2[4] & b[1]; // NOLINT
  r[6] ^= a2[5] & b[1]; // NOLINT
  r[7] ^= a2[6] & b[1]; // NOLINT
  a2[7] ^= a2[6]; /* reduce */ // NOLINT
  a2[1] ^= a2[6]; // NOLINT
  a2[2] ^= a2[6]; // NOLINT
// NOLINT
  r[0] ^= a2[6] & b[2]; /* add */ // NOLINT
  r[1] ^= a2[7] & b[2]; // NOLINT
  r[2] ^= a2[0] & b[2]; // NOLINT
  r[3] ^= a2[1] & b[2]; // NOLINT
  r[4] ^= a2[2] & b[2]; // NOLINT
  r[5] ^= a2[3] & b[2]; // NOLINT
  r[6] ^= a2[4] & b[2]; // NOLINT
  r[7] ^= a2[5] & b[2]; // NOLINT
  a2[6] ^= a2[5]; /* reduce */ // NOLINT
  a2[0] ^= a2[5]; // NOLINT
  a2[1] ^= a2[5]; // NOLINT
// NOLINT
  r[0] ^= a2[5] & b[3]; /* add */ // NOLINT
  r[1] ^= a2[6] & b[3]; // NOLINT
  r[2] ^= a2[7] & b[3]; // NOLINT
  r[3] ^= a2[0] & b[3]; // NOLINT
  r[4] ^= a2[1] & b[3]; // NOLINT
  r[5] ^= a2[2] & b[3]; // NOLINT
  r[6] ^= a2[3] & b[3]; // NOLINT
  r[7] ^= a2[4] & b[3]; // NOLINT
  a2[5] ^= a2[4]; /* reduce */ // NOLINT
  a2[7] ^= a2[4]; // NOLINT
  a2[0] ^= a2[4]; // NOLINT
// NOLINT
  r[0] ^= a2[4] & b[4]; /* add */ // NOLINT
  r[1] ^= a2[5] & b[4]; // NOLINT
  r[2] ^= a2[6] & b[4]; // NOLINT
  r[3] ^= a2[7] & b[4]; // NOLINT
  r[4] ^= a2[0] & b[4]; // NOLINT
  r[5] ^= a2[1] & b[4]; // NOLINT
  r[6] ^= a2[2] & b[4]; // NOLINT
  r[7] ^= a2[3] & b[4]; // NOLINT
  a2[4] ^= a2[3]; /* reduce */ // NOLINT
  a2[6] ^= a2[3]; // NOLINT
  a2[7] ^= a2[3]; // NOLINT
// NOLINT
  r[0] ^= a2[3] & b[5]; /* add */ // NOLINT
  r[1] ^= a2[4] & b[5]; // NOLINT
  r[2] ^= a2[5] & b[5]; // NOLINT
  r[3] ^= a2[6] & b[5]; // NOLINT
  r[4] ^= a2[7] & b[5]; // NOLINT
  r[5] ^= a2[0] & b[5]; // NOLINT
  r[6] ^= a2[1] & b[5]; // NOLINT
  r[7] ^= a2[2] & b[5]; // NOLINT
  a2[3] ^= a2[2]; /* reduce */ // NOLINT
  a2[5] ^= a2[2]; // NOLINT
  a2[6] ^= a2[2]; // NOLINT
// NOLINT
  r[0] ^= a2[2] & b[6]; /* add */ // NOLINT
  r[1] ^= a2[3] & b[6]; // NOLINT
  r[2] ^= a2[4] & b[6]; // NOLINT
  r[3] ^= a2[5] & b[6]; // NOLINT
  r[4] ^= a2[6] & b[6]; // NOLINT
  r[5] ^= a2[7] & b[6]; // NOLINT
  r[6] ^= a2[0] & b[6]; // NOLINT
  r[7] ^= a2[1] & b[6]; // NOLINT
  a2[2] ^= a2[1]; /* reduce */ // NOLINT
  a2[4] ^= a2[1]; // NOLINT
  a2[5] ^= a2[1]; // NOLINT
// NOLINT
  r[0] ^= a2[1] & b[7]; /* add */ // NOLINT
  r[1] ^= a2[2] & b[7]; // NOLINT
  r[2] ^= a2[3] & b[7]; // NOLINT
  r[3] ^= a2[4] & b[7]; // NOLINT
  r[4] ^= a2[5] & b[7]; // NOLINT
  r[5] ^= a2[6] & b[7]; // NOLINT
  r[6] ^= a2[7] & b[7]; // NOLINT
  r[7] ^= a2[0] & b[7]; // NOLINT
} // NOLINT
// NOLINT
/* // NOLINT
 * Square `x` in GF(2^8) and write the result to `r`. `r` and `x` may overlap. // NOLINT
 */ // NOLINT
static void gf256_square(uint32_t r[8], const uint32_t x[8]) { // NOLINT
  // NOLINT
  uint32_t r8, r10, r12, r14; // NOLINT
  /* Use the Freshman's Dream rule to square the polynomial // NOLINT
   * Assignments are done from 7 downto 0, because this allows the user // NOLINT
   * to execute this function in-place (e.g. `gf256_square(r, r);`). // NOLINT
   */ // NOLINT
  r14 = x[7]; // NOLINT
  r12 = x[6]; // NOLINT
  r10 = x[5]; // NOLINT
  r8 = x[4]; // NOLINT
  r[6] = x[3]; // NOLINT
  r[4] = x[2]; // NOLINT
  r[2] = x[1]; // NOLINT
  r[0] = x[0]; // NOLINT
// NOLINT
  /* Reduce with  x^8 + x^4 + x^3 + x + 1 until order is less than 8 */ // NOLINT
  r[7] = r14; /* r[7] was 0 */ // NOLINT
  r[6] ^= r14; // NOLINT
  r10 ^= r14; // NOLINT
  /* Skip, because r13 is always 0 */ // NOLINT
  r[4] ^= r12; // NOLINT
  r[5] = r12; /* r[5] was 0 */ // NOLINT
  r[7] ^= r12; // NOLINT
  r8 ^= r12; // NOLINT
  /* Skip, because r11 is always 0 */ // NOLINT
  r[2] ^= r10; // NOLINT
  r[3] = r10; /* r[3] was 0 */ // NOLINT
  r[5] ^= r10; // NOLINT
  r[6] ^= r10; // NOLINT
  r[1] = r14;  /* r[1] was 0 */ // NOLINT
  r[2] ^= r14; /* Substitute r9 by r14 because they will always be equal*/ // NOLINT
  r[4] ^= r14; // NOLINT
  r[5] ^= r14; // NOLINT
  r[0] ^= r8; // NOLINT
  r[1] ^= r8; // NOLINT
  r[3] ^= r8; // NOLINT
  r[4] ^= r8; // NOLINT
} // NOLINT
// NOLINT
/* // NOLINT
 * Invert `x` in GF(2^8) and write the result to `r` // NOLINT
 */ // NOLINT
static void gf256_inv(uint32_t r[8], uint32_t x[8]) { // NOLINT
  // NOLINT
  uint32_t y[8], z[8]; // NOLINT
// NOLINT
  gf256_square(y, x); // y = x^2 // NOLINT
  gf256_square(y, y); // y = x^4 // NOLINT
  gf256_square(r, y); // r = x^8 // NOLINT
  gf256_mul(z, r, x); // z = x^9 // NOLINT
  gf256_square(r, r); // r = x^16 // NOLINT
  gf256_mul(r, r, z); // r = x^25 // NOLINT
  gf256_square(r, r); // r = x^50 // NOLINT
  gf256_square(z, r); // z = x^100 // NOLINT
  gf256_square(z, z); // z = x^200 // NOLINT
  gf256_mul(r, r, z); // r = x^250 // NOLINT
  gf256_mul(r, r, y); // r = x^254 // NOLINT
} // NOLINT
// NOLINT
/* // NOLINT
 * Create `k` key shares of the key given in `key`. The caller has to ensure // NOLINT
 * that the array `out` has enough space to hold at least `n` sss_Keyshare // NOLINT
 * structs. // NOLINT
 */ // NOLINT
void sss_create_keyshares(sss_Keyshare *out, const uint8_t key[32], uint8_t n, // NOLINT
                          uint8_t k) { // NOLINT // NOLINT
  // NOLINT
  /* Check if the parameters are valid */ // NOLINT
  assert(n != 0); // NOLINT
  assert(k != 0); // NOLINT
  assert(k <= n); // NOLINT
// NOLINT
  uint8_t share_idx, coeff_idx; // NOLINT
  uint32_t poly0[8], poly[k - 1][8], x[8], y[8], xpow[8], tmp[8]; // NOLINT
// NOLINT
  /* Put the secret in the bottom part of the polynomial */ // NOLINT
  bitslice(poly0, key); // NOLINT
// NOLINT
  /* Generate the other terms of the polynomial */ // NOLINT
  randombytes((void *)poly, sizeof(poly)); // NOLINT
// NOLINT
  for (share_idx = 0; share_idx < n; share_idx++) { // NOLINT
    // NOLINT
    /* x value is in 1..n */ // NOLINT
    uint8_t unbitsliced_x = share_idx + 1; // NOLINT
    out[share_idx][0] = unbitsliced_x; // NOLINT
    bitslice_setall(x, unbitsliced_x); // NOLINT
// NOLINT
    /* Calculate y */ // NOLINT
    memset(y, 0, sizeof(y)); // NOLINT
    memset(xpow, 0, sizeof(xpow)); // NOLINT
    xpow[0] = ~0; // NOLINT
    gf256_add(y, poly0); // NOLINT
    for (coeff_idx = 0; coeff_idx < (k - 1); coeff_idx++) { // NOLINT
      // NOLINT
      gf256_mul(xpow, xpow, x); // NOLINT
      gf256_mul(tmp, xpow, poly[coeff_idx]); // NOLINT
      gf256_add(y, tmp); // NOLINT
    } // NOLINT
    unbitslice(&out[share_idx][1], y); // NOLINT
  } // NOLINT
} // NOLINT
// NOLINT
/* // NOLINT
 * Restore the `k` sss_Keyshare structs given in `shares` and write the result // NOLINT
 * to `key`. // NOLINT
 */ // NOLINT
void sss_combine_keyshares(uint8_t key[32], const sss_Keyshare *key_shares, // NOLINT
                           uint8_t k) { // NOLINT
  // NOLINT
  size_t share_idx, idx1, idx2; // NOLINT
  uint32_t xs[k][8], ys[k][8]; // NOLINT
  uint32_t num[8], denom[8], tmp[8]; // NOLINT
  uint32_t secret[8] = {0}; // NOLINT
// NOLINT
  /* Collect the x and y values */ // NOLINT
  for (share_idx = 0; share_idx < k; share_idx++) { // NOLINT
    // NOLINT
    bitslice_setall(xs[share_idx], key_shares[share_idx][0]); // NOLINT
    bitslice(ys[share_idx], &key_shares[share_idx][1]); // NOLINT
  } // NOLINT
// NOLINT
  /* Use Lagrange basis polynomials to calculate the secret coefficient */ // NOLINT
  for (idx1 = 0; idx1 < k; idx1++) { // NOLINT
    // NOLINT
    memset(num, 0, sizeof(num)); // NOLINT
    memset(denom, 0, sizeof(denom)); // NOLINT
    num[0] = ~0;   /* num is the numerator (=1) */ // NOLINT
    denom[0] = ~0; /* denom is the numerator (=1) */ // NOLINT
    for (idx2 = 0; idx2 < k; idx2++) { // NOLINT
      // NOLINT
      if (idx1 == idx2) // NOLINT
        continue; // NOLINT
      gf256_mul(num, num, xs[idx2]); // NOLINT
      memcpy(tmp, xs[idx1], sizeof(uint32_t[8])); // NOLINT
      gf256_add(tmp, xs[idx2]); // NOLINT
      gf256_mul(denom, denom, tmp); // NOLINT
    } // NOLINT
    gf256_inv(tmp, denom);         /* inverted denominator */ // NOLINT
    gf256_mul(num, num, tmp);      /* basis polynomial */ // NOLINT
    gf256_mul(num, num, ys[idx1]); /* scaled coefficient */ // NOLINT
    gf256_add(secret, num); // NOLINT
  } // NOLINT
  unbitslice(key, secret); // NOLINT
} // NOLINT
// NOLINT
