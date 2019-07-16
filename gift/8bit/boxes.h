/**
 * Sbox (and Pbox) implementations for the GIFT cypher utilizing 8-bit native
 * data types.
 *
 * Riley Myers (william.myers@inl.gov)
 * 07.15.19
 *
 * Based on work done by Dirk Klose and Embedded Security Group of
 * Ruhr-Universitaet Bochum, Germany.
 **/

#pragma once
#include <stdint.h>

// GIFT ?
/*
const uint8_t Sbox[16] = { 0x1, 0xa, 0x4, 0xc, 0x6, 0xf, 0x3, 0x9,
                           0x2, 0xd, 0xb, 0x7, 0x5, 0x0, 0x8, 0xe };

const uint8_t SboxInv[16] = { 0xd, 0x0, 0x8, 0x6, 0x2, 0xc, 0x4, 0xb,
                              0xd, 0x7, 0x1, 0xa, 0x3, 0x9, 0xf, 0x5 };
                              */
// PRESENT
const uint8_t Sbox[16]    = { 0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd,
                           0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2 };
const uint8_t SboxInv[16] = { 0x5, 0xe, 0xf, 0x8, 0xc, 0x1, 0x2, 0xd,
                              0xb, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xa };
