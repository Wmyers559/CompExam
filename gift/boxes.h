/*
 * S-Boxes and P-Boxes for
 * Implementation of PRESENT in C
 * v2.1, 10/13/2008
 *
 * Thomas Siebert, thomas.siebert@rub.de
 */

const uint8_t Sbox[16] = // changed to use GIFT structure
  { 1, 0xa, 4, 0xc, 6, 0xf, 3, 9, 2, 0xd, 0xb, 7, 5, 0, 8, 0xe };

const uint8_t SboxInv[16] = // Changed to use GIFT structure
  { 13, 0, 8, 6, 2, 12, 4, 11, 14, 7, 1, 10, 3, 9, 15, 5 };

const uint8_t PboxInv[64] = { 0,  5,  10, 15, 16, 21, 26, 31, 32, 37, 42,
                              47, 48, 53, 58, 63, 12, 1,  6,  11, 28, 17,
                              22, 27, 44, 33, 38, 43, 60, 49, 54, 59, 8,
                              13, 2,  7,  24, 29, 18, 23, 40, 45, 34, 39,
                              56, 61, 50, 55, 4,  9,  14, 3,  20, 25, 30,
                              19, 36, 41, 46, 35, 52, 57, 62, 51 };

const uint8_t Pbox[64] = { 0,  17, 34, 51, 48, 1,  18, 35, 32, 49, 2,  19, 16,
                           33, 50, 3,  4,  21, 38, 55, 52, 5,  22, 39, 36, 53,
                           6,  23, 20, 37, 54, 7,  8,  25, 42, 59, 56, 9,  26,
                           43, 40, 57, 10, 27, 24, 41, 58, 11, 12, 29, 46, 63,
                           60, 13, 30, 47, 44, 61, 14, 31, 28, 45, 62, 15 };

const uint8_t Pbox128[128] = {
    0,  33, 66, 99,  96,  1,  34, 67, 64, 97,  2,  35, 32, 65, 98,  3,
    4,  37, 70, 103, 100, 5,  38, 71, 68, 101, 6,  39, 36, 69, 102, 7,
    8,  41, 74, 107, 104, 9,  42, 75, 72, 105, 10, 43, 40, 73, 106, 11,
    12, 45, 78, 111, 108, 13, 46, 79, 76, 109, 14, 47, 44, 77, 110, 15,
    16, 49, 82, 115, 112, 17, 50, 83, 80, 113, 18, 51, 48, 81, 114, 19,
    20, 53, 86, 119, 116, 21, 54, 87, 84, 117, 22, 55, 52, 85, 118, 23,
    24, 57, 90, 123, 120, 25, 58, 91, 88, 121, 26, 59, 56, 89, 122, 27,
    28, 61, 94, 127, 124, 29, 62, 95, 92, 125, 30, 63, 60, 93, 126, 31
};

const uint8_t Pbox128Inv[128] = {
    0,  5,  10, 15, 16, 21, 26, 31, 32,  37,  42,  47,  48,  53,  58,  63,
    64, 69, 74, 79, 80, 85, 90, 95, 96,  101, 106, 111, 112, 117, 122, 127,
    12, 1,  6,  11, 28, 17, 22, 27, 44,  33,  38,  43,  60,  49,  54,  59,
    76, 65, 70, 75, 92, 81, 86, 91, 108, 97,  102, 107, 124, 113, 118, 123,
    8,  13, 2,  7,  24, 29, 18, 23, 40,  45,  34,  39,  56,  61,  50,  55,
    72, 77, 66, 71, 88, 93, 82, 87, 104, 109, 98,  103, 120, 125, 114, 119,
    4,  9,  14, 3,  20, 25, 30, 19, 36,  41,  46,  35,  52,  57,  62,  51,
    68, 73, 78, 67, 84, 89, 94, 83, 100, 105, 110, 99,  116, 121, 126, 115
};

const uint8_t Constants[48] = // Added to use GIFT structure
  { 0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3e, 0x3d, 0x3b, 0x37, 0x2f, 0x1e, 0x3c,
    0x39, 0x33, 0x27, 0x0e, 0x1d, 0x3a, 0x35, 0x2b, 0x16, 0x2c, 0x18, 0x30,
    0x21, 0x02, 0x05, 0x0b, 0x17, 0x2e, 0x1c, 0x38, 0x31, 0x23, 0x06, 0x0d,
    0x1b, 0x36, 0x2d, 0x1a, 0x34, 0x29, 0x12, 0x24, 0x08, 0x11, 0x22, 0x04 };

const uint8_t ConstantsLocation[6] = { 3, 7, 11, 15, 19, 23 };
