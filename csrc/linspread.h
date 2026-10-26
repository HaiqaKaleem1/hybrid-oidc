/* linspread.h — GF(2)-linear diffusion layer (the linear-algebra component).
 *
 * The 512-bit state (the 64-byte hybrid secret) is viewed as a vector over
 * F_2 and multiplied by a public, fixed, invertible 512x512 matrix M:
 *
 *   M = T^3,  T = I + S1*R13 + S2*R11 + S4*R31 + S5*R47
 *
 * where S_k cyclically permutes the eight 64-bit words and R_r rotates bits
 * within a word. Both are permutation matrices over F_2, so T (and M) is
 * F_2-linear; rank(M) = 512 (full) and every output word depends on every
 * input word (properties verified exactly by tools/linspread_check.py).
 *
 * Implementation cost: 3 rounds x 5 XOR-rotates per word = 120 XOR/ROT
 * operations, straight-line, no branches, no tables.
 */
#ifndef HMK_LINSPREAD_H
#define HMK_LINSPREAD_H

#include <stdint.h>

void hmk_linspread(uint8_t out[64], const uint8_t in[64]);

#endif
