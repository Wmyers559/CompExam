/*
 * S-Boxes and P-Boxes for
 * Implementation of PRESENT in C
 * v2.1, 10/13/2008
 *
 * Thomas Siebert, thomas.siebert@rub.de
 */

const uint8_t Sbox[16] = // changed to use GIFT structure base 3 oxf occurs in an error
  { 6, 0xa, 4, 0xf, 1, 8, 2, 0xf, 0, 5, 9, 0xf, 0xf, 0xf, 0xf, 0xf };

const uint8_t SboxInv[16] = // Changed to use GIFT structure base 3 oxf occurs in an error
  { 8, 4, 6, 0xf, 2, 9, 0, 0xf, 5, 0xa, 1, 0xf, 0xf, 0xf, 0xf, 0xf };
  
  
/*
 * const uint8_t Sbox[16] =  Extra Version 1
 *      { 1, 2, 0, 0xf, 5, 6, 4, 0xf, 9, 0xa, 8, 0xf, 0xf, 0xf, 0xf, 0xf };
 * 
 * const uint8_t SboxInv[16] Extra Version 1 Inv
 * { 2, 0, 1, 0xf, 6, 4, 5, 0xf, 0xa, 8, 9, 0xf, 0xf, 0xf, 0xf, 0xf };
 * 
 *  * const uint8_t Sbox[16] =  Extra Version 2
 *      { 8, 9, 0xa, 0xf, 0, 1, 2, 0xf, 4, 5, 6, 0xf, 0xf, 0xf, 0xf, 0xf };
 * 
 * const uint8_t SboxInv[16] Extra Version 2 Inv
 * { 4, 5, 6, 0xf, 8, 9, 0xa, 0xf, 0, 1, 2, 0xf, 0xf, 0xf, 0xf, 0xf };
 * 
 * 
 *  * const uint8_t Sbox[16] =  Extra Version 3
 *      { 0xa, 4, 8, 0xf, 6, 2, 1, 0xf, 5, 0, 9, 0xf, 0xf, 0xf, 0xf, 0xf };
 * 
 * const uint8_t SboxInv[16] Extra Version 3 Inv
 * { 9, 6, 5, 0xf, 1, 8, 4, 0xf, 2, 0xa, 0, 0xf, 0xf, 0xf, 0xf, 0xf };
 * 
 * 
 * 
 * 
 * 
 */
  
  
  
const uint8_t Pbox[32] = {0,9,18,27,24,1,10,19,
                            16,25,2,11,8,17,26,3,
                            4,13,22,31,28,5,14,23,
                            20,29,6,15,12,21,30,7
};

const uint8_t PboxInv[32] = {0,5,10,15,16,21,26,31,
                            12,1,6,11,28,17,22,27,
                            8,13,2,7,24,29,18,23,
                            4,9,14,3,20,25,30,19
    
};
  
  /* PRESENT style look up table
const uint8_t PboxInv[32] = { 0,4,8,12,16,20,24,28,
                                1,5,9,13,17,21,25,29,
                                2,6,10,14,18,22,26,30,
                                3,7,11,15,19,23,27,31
};

const uint8_t Pbox[32] = { 0, 8,16, 24,1,9,17,25,
                            2,10,18,26,3,11,19,27,
                            4,12,20,28,5,13,21,29,
                            6,14,22,30,7,15,23,31
};
*/


const uint8_t Pbox128Inv[64] = { 0,  5,  10, 15, 16, 21, 26, 31, 32, 37, 42,
                              47, 48, 53, 58, 63, 12, 1,  6,  11, 28, 17,
                              22, 27, 44, 33, 38, 43, 60, 49, 54, 59, 8,
                              13, 2,  7,  24, 29, 18, 23, 40, 45, 34, 39,
                              56, 61, 50, 55, 4,  9,  14, 3,  20, 25, 30,
                              19, 36, 41, 46, 35, 52, 57, 62, 51 };

const uint8_t Pbox128[64] = { 0,  17, 34, 51, 48, 1,  18, 35, 32, 49, 2,  19, 16,
                           33, 50, 3,  4,  21, 38, 55, 52, 5,  22, 39, 36, 53,
                           6,  23, 20, 37, 54, 7,  8,  25, 42, 59, 56, 9,  26,
                           43, 40, 57, 10, 27, 24, 41, 58, 11, 12, 29, 46, 63,
                           60, 13, 30, 47, 44, 61, 14, 31, 28, 45, 62, 15 };

/* PRESENT like Permutations

const uint8_t Pbox128[64] = {
		0, 4, 8, 12, 16, 20, 24, 28,
		32, 36, 40, 44, 48, 52,	56, 60,
		1, 5, 9, 13, 17, 21, 25, 29,
		33, 37, 41, 45, 49,	53, 57, 61,
		2, 6, 10, 14, 18, 22, 26, 30,
		34, 38, 42, 46,	50, 54, 58, 62,
		3, 7, 11, 15, 19, 23, 27, 31,
		35, 39, 43,	47, 51, 55, 59, 63
};

const uint8_t Pbox128Inv[64] = {
		0, 16, 32, 48, 1, 17, 33, 49,
		2, 18, 34, 50, 3, 19, 35, 51,
		4, 20, 36, 52, 5, 21, 37, 53,
		6, 22, 38, 54, 7, 23, 39, 55,
		8, 24, 40, 56, 9, 25, 41, 57,
		10, 26, 42, 58, 11, 27, 43, 59,
		12, 28, 44, 60, 13, 29, 45, 61,
		14, 30, 46, 62, 15, 31, 47, 63 
};
*/

const uint8_t Constants[48] = // Added to use GIFT structure
  { 0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3e, 0x3d, 0x3b, 0x37, 0x2f, 0x1e, 0x3c,
    0x39, 0x33, 0x27, 0x0e, 0x1d, 0x3a, 0x35, 0x2b, 0x16, 0x2c, 0x18, 0x30,
    0x21, 0x02, 0x05, 0x0b, 0x17, 0x2e, 0x1c, 0x38, 0x31, 0x23, 0x06, 0x0d,
    0x1b, 0x36, 0x2d, 0x1a, 0x34, 0x29, 0x12, 0x24, 0x08, 0x11, 0x22, 0x04 };

const uint8_t ConstantsLocation[6] = { 3, 7, 11, 15, 19, 23 };
