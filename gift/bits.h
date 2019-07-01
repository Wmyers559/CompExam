/**
 * Bit-manipulation macros for an implementation of GIFT/PRESENT in C
 *
 * Modularized by Riley Myers (william.myers@inl.gov)
 */

#pragma once

//----------------------------------
// Macros for bit manipulation
//----------------------------------                                returns...
#define high45_64(h45in) ((uint64_t)h45in >> 9)           // 45 msb as lsb
#define high61_64(h4in) ((uint64_t)h4in >> 3)             // 61 msb as lsb
#define high4_64(h4in) ((uint64_t)h4in >> 60)             // 4 msb as lsb
#define high8to4_64(h8in) (((uint64_t)h8in >> 56) & 0x0F) // 4 msb as 2. lsb
#define high16_64(h16in) ((uint64_t)h16in >> 48)          // 16 msb as lsb
#define high1_64(h1in) ((uint64_t)h1in >> 63)             // msb as lsb
#define low4_64(l4in) ((uint64_t)l4in << 60)              // 4 lsb as msb
#define low8to4_64(l4in) ((uint64_t)l4in << 56)           // 4 lsb as 2. msb
#define low16_64(l4in) ((uint64_t)l4in << 48)             // 4 lsb as msb
#define rotate1l_64(r1lin)                                                     \
    (high1_64(r1lin) | (r1lin << 1)) // input rotated left (1x)
#define rotate1r_64(r1rin)                                                     \
    (high1_64(r1rin) | (r1rin >> 1)) // input rotated right (1x)
#define rotate4l_64(r4lin)                                                     \
    (high4_64(r4lin) | (r4lin << 4)) // input rotated left (4x)
#define rotate4r_64(r4rin)                                                     \
    (high4_64(r4rin) | (r4rin >> 4)) // input rotated right (4x)
#define getBit(in, bitNum) (((uint64_t)in >> bitNum) & 0x01)
#define setBit(src, in, bitNum) (((uint64_t)in << bitNum) | (uint64_t)src)

#define rotateRight16Bit(in, bitNum)                                           \
    (((in >> bitNum) | (in << (16 - bitNum))) & (0xffff))
