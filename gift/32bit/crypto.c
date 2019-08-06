/**
 * Implementation of GIFT in C, cryptographic core functions
 *
 * Dirk Klose
 * Riley Myers (william.myers@inl.gov)
 *
 */

#include "crypto.h"
#include "boxes.h"
#include <stdint.h>

#define True  1
#define False 0
//----------------------------------
// Utility functions
//----------------------------------

/**
 * Generate the round constants utilizing the 6-bit affine LFSR described in the
 * paper. This recalculates the entire sequence each time to save space and
 * allow for multiple calls of the same round.
 */

uint8_t
constants_time(uint8_t round)
{
    uint8_t c = 0;

    for (uint8_t i = 0; i <= round; i++) {
        c = ((c & 0x1f) << 1) | (1 ^ ((c >> 4) & 0x1) ^ ((c >> 5) & 0x1));
    }
    return c;
}

/**
 * Generate the round constants utilizing the 6-bit affine LFSR described in the
 * paper. This stores the sequence in an internal static variable and only
 * advances the sequence if the `advance` parameter is non-zero. To reset the
 * sequence, the `reset` parameter should be non-zero.
 */

uint8_t
constants_space(uint8_t advance, uint8_t reset)
{
    static uint8_t c = 0;

    if (reset) {
        c = 0;
    }

    if (advance) {
        c = ((c & 0x1f) << 1) | (1 ^ ((c >> 4) & 0x1) ^ ((c >> 5) & 0x1));
    }

    return c;
}

/**
 * Computes the round key for the given round and key state. it returns the
 * value in `k`, which should point to an array of eight/sixteen bytes to store
 * the round key in.
 */

uint8_t
round_key64(const uint16_t* key_state, uint32_t* k)
{
    uint8_t i;
    uint16_t u = 0;
    uint16_t v = 0;

    // V = k_0 , U = k_1 (16 bit words)
    v = key_state[0];
    u = key_state[1];

    // zero out previous round key
    k[0] = 0;
    k[1] = 0;

    // introduce keystate to the round key
    for (i = 0; i < 16; i++) {
        uint8_t j = 4 * i;
        k[j / 32] |= ((v >> i) & 0x1) << (j % 32);
        k[(j + 1) / 32] |= ((u >> i) & 0x1) << ((j + 1) % 32);
    }

    // Add in constants
    for (uint8_t c = constants_space(True, False), i = 0; i < 6; i++) {
        // Constants are inserted at bit positions 23, 19, 15, 11, 7, 3
        uint8_t j = 3 + 4 * i;
        k[0] |= ((c >> i) & 0x1) << j;
    }

    // unconditionally set the upper bit on the round key
    k[1] |= 0x80000000;

    return 0;
}

uint8_t
round_key128(const uint16_t* key_state, uint32_t* k)
{
    uint8_t i;
    uint32_t u = 0;
    uint32_t v = 0;

    // V = k_1 || k_0 , U = k_5 || k_4 (16 bit words)
    v = ((uint32_t)key_state[1] << 16) | key_state[0];
    u = ((uint32_t)key_state[5] << 16) | key_state[4];

    // zero out previous round key
    for (i = 0; i < 4; i++) {
        k[i] = 0;
    }

    // introduce keystate to the round key
    for (i = 0; i < 32; i++) {
        uint8_t j = 4 * i + 1;
        k[j / 32] |= ((v >> i) & 0x1) << (j % 32);
        k[(j + 1) / 32] |= ((u >> i) & 0x1) << ((j + 1) % 32);
    }

    // Add in constants
    for (uint8_t c = constants_space(True, False), i = 0; i < 6; i++) {
        // Constants are inserted at bit positions 23, 19, 15, 11, 7, 3
        uint8_t j = 3 + 4 * i;
        k[0] |= ((c >> i) & 0x1) << j;
    }

    // unconditionally set the upper bit on the round key
    k[3] |= 0x80000000;

    return 0;
}

/**
 * These exploit the clever design of the GIFT permutation that the destination
 *   bits of the permutation are patterned in groups of four, and the pattern is
 *   such that it is a function of the bit number in the group, plus an offset
 *   based on which group of four it is.
 *
 * For example, the gift permutation for the 64-bit version for the first 16 bit
 *   cypherstate is as follows:
 *
 *   j    | 0   1   2   3  |  4   5   6   7  |  8   9  10  11 |  12  13  14  15
 * ----------------------------------------------------------------------------
 * s_0(j) | 0  12   8   4  |  1   13  9   5  |  2  14  10  6  |  3   15  11  7
 *
 * As such, the permutation is a function mapping bit 0 of the nybble to bit
 *   (0 * 4), bit 1 to bit (3 * 4), bit 2 to bit (2 * 4), and bit 3 to bit (1 *
 *   4). This is also combined with an offset of the number of the nybble.
 *   Between the different rows of cypherstate, only these bit mappings change.
 *
 * These functions process the cypherstate as a series of nybbles, specifically
 * for the bitslice implementation.
 */
uint16_t
rowperm16(uint16_t s, uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3)
{
    uint16_t tmp = 0;
    for (uint8_t b = 0; b < 4; b++) {
        tmp |= ((s >> (4 * b + 0) & 0x1) << (b + 4 * b0));
        tmp |= ((s >> (4 * b + 1) & 0x1) << (b + 4 * b1));
        tmp |= ((s >> (4 * b + 2) & 0x1) << (b + 4 * b2));
        tmp |= ((s >> (4 * b + 3) & 0x1) << (b + 4 * b3));
    }

    return tmp;
}

uint32_t
rowperm32(uint32_t s, uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3)
{
    uint32_t tmp = 0;
    for (uint8_t b = 0; b < 8; b++) {
        tmp |= ((s >> (4 * b + 0) & 0x1) << (b + 8 * b0));
        tmp |= ((s >> (4 * b + 1) & 0x1) << (b + 8 * b1));
        tmp |= ((s >> (4 * b + 2) & 0x1) << (b + 8 * b2));
        tmp |= ((s >> (4 * b + 3) & 0x1) << (b + 8 * b3));
    }

    return tmp;
}

//----------------------------------
// Encryption
//----------------------------------

// These encrypt the plaintext using a pregenerated subkey array
uint8_t
encrypt(uint64_t in, uint64_t* subkey, uint16_t Rounds)
{
    return 0;
}

uint8_t
encrypt128(uint64_t inHigh, uint64_t inLow, uint64_t* subkey, uint16_t Rounds)
{
    return 0;
}

// These encrypt and generate the key schedule on the fly, saving memory at the
// cost of more computations. This does mangle the plaintext passed in, since
// the result of the encryption is returned in-place
uint8_t
e64_fly(uint8_t* text, uint8_t* key, uint16_t Rounds)
{
    //  Counter
    uint8_t i = 0;
    //  p variables
    uint8_t  pos       = 0;
    uint8_t  elem_src  = 0;
    uint8_t  bit_src   = 0;
    uint8_t  elem_dest = 0;
    uint8_t  bit_dest  = 0;
    uint32_t p_buf[2];
    //  Key scheduling variables
    uint16_t rot[2] = { 0 };
    //  Cypher/key state and round key
    uint16_t keystate[8] = { 0 };
    uint32_t state[2]    = { 0 };
    uint32_t rk[2]       = { 0 };

    /* Setup state */
    state[0] = ((uint32_t)text[3] << 24) | ((uint32_t)text[2] << 16) |
               ((uint32_t)text[1] << 8)  | ((uint32_t)text[0]);
    state[1] = ((uint32_t)text[7] << 24) | ((uint32_t)text[6] << 16) |
               ((uint32_t)text[5] << 8)  | ((uint32_t)text[4]);

    for (i = 0; i < 8; i++) {
        keystate[i] = ((uint16_t)key[2 * i + 1] << 8) | ((uint16_t)key[2 * i]);
    }

    for (uint8_t round = 0; round < Rounds; round++) {

        /**************** Sbox application ****************/
        uint32_t tmp[2];

        for (i = 0, tmp[0] = 0, tmp[1] = 0; i < 8; i++) {
            tmp[0] |= Sbox[(state[0] >> (i * 4)) & 0xf] << (i * 4);
            tmp[1] |= Sbox[(state[1] >> (i * 4)) & 0xf] << (i * 4);
        }

        /**************** Permutation stage ****************/
        p_buf[0] = 0;
        p_buf[1] = 0;

        for (i = 0; i < 64; i++) {
            pos = 4 * (i / 16) +
                  16 * ((3 * ((i % 16) / 4) + (i % 4)) % 4) + (i % 4);

            // This operates doubly backwards for compatibility with Will
            // Unger's version
            elem_src  = (63 - pos) / 32;
            bit_src   = (63 - pos) % 32;
            elem_dest = (63 - i) / 32;
            bit_dest  = (63 - i) % 32;

            p_buf[elem_dest] |= ((tmp[elem_src] >> bit_src) & 0x1) << bit_dest;
        }

        /******************** Key addition ********************/
        round_key64(keystate, rk);
        state[0] = p_buf[0] ^ rk[0];
        state[1] = p_buf[1] ^ rk[1];

        /******************* Key scheduling *******************/

        rot[0] = keystate[0];
        rot[1] = keystate[1];

        for ( i = 0; i < 6; i++) {
            keystate[i] = keystate[i + 2];
        }
        keystate[6] = (rot[0] >> 12) | (rot[0] << 4);
        keystate[7] = (rot[1] >>  2) | (rot[1] << 14);
    }

    for (i = 0; i < 2; i++) {
        text[4 * i + 3] = state[i] >> 24;
        text[4 * i + 2] = state[i] >> 16;
        text[4 * i + 1] = state[i] >> 8;
        text[4 * i + 0] = state[i];
    }

    return 0;
}

uint8_t
e128_fly(uint8_t* text, uint8_t* key, uint16_t Rounds)
{
    //  Counter
    uint8_t i = 0;
    //  p variables
    uint8_t  pos       = 0;
    uint8_t  elem_src  = 0;
    uint8_t  bit_src   = 0;
    uint8_t  elem_dest = 0;
    uint8_t  bit_dest  = 0;
    uint32_t p_buf[4];
    //  Key scheduling variables
    uint16_t rot[2] = { 0 };
    //  Cypher/key state and round key
    uint16_t keystate[8] = { 0 };
    uint32_t state[4]    = { 0 };
    uint32_t rk[4]       = { 0 };

    /* Setup state */
    for (i = 0; i < 16; i++) {
        state[i / 4] |= (uint32_t)text[i] << ((i % 4) * 8);
    }

    for (i = 0; i < 8; i++) {
        keystate[i] = ((uint16_t)key[2 * i + 1] << 8) | ((uint16_t)key[2 * i]);
    }

    for (uint8_t round = 0; round < Rounds; round++) {

        /**************** Sbox application ****************/
        uint32_t s[4]; // Sbox results

        for (i = 0, s[0] = 0, s[1] = 0, s[2] = 0, s[3] = 0; i < 8; i++) {
            s[0] |= Sbox[(state[0] >> (i * 4)) & 0xf] << (i * 4);
            s[1] |= Sbox[(state[1] >> (i * 4)) & 0xf] << (i * 4);
        }

        /**************** Permutation stage ****************/
        p_buf[0] = 0;
        p_buf[1] = 0;
        p_buf[2] = 0;
        p_buf[3] = 0;

        for (i = 0; i < 128; i++) {
            pos = 4 * (i / 16) +
                  32 * ((3 * ((i % 16) / 4) + (i % 4)) % 4) + (i % 4);

            elem_src  = (i) / 32;
            bit_src   = (i) % 32;
            elem_dest = (pos) / 32;
            bit_dest  = (pos) % 32;

            p_buf[elem_dest] |= ((s[elem_src] >> bit_src) & 0x1) << bit_dest;
        }

        /******************** Key addition ********************/
        round_key128(keystate, rk);
        for (i = 0; i < 4; i++) {
            state[i] = p_buf[i] ^ rk[i];
        }

        /******************* Key scheduling *******************/

        rot[0] = keystate[0];
        rot[1] = keystate[1];

        for ( i = 0; i < 6; i++) {
            keystate[i] = keystate[i + 2];
        }
        keystate[6] = (rot[0] >> 12) | (rot[0] << 4);
        keystate[7] = (rot[1] >>  2) | (rot[1] << 14);
    }

    for (i = 0; i < 4; i++) {
        text[4 * i + 3] = state[i] >> 24;
        text[4 * i + 2] = state[i] >> 16;
        text[4 * i + 1] = state[i] >> 8;
        text[4 * i + 0] = state[i];
    }

    return 0;
}


// These use an efficient bit-slice implementation of the algorithm, mirroring
// the reference implementation in the GIFT-COFB NIST submission
uint8_t
e64_slice(uint8_t* state, uint8_t* key, uint16_t Rounds)
{
    uint16_t s[4];  /* Cypherstate */
    uint16_t t[8];  /* Keystate */

    /* Copy input into state arrays */
    for (uint8_t i = 0; i < 4; i++){
        s[i]     = ((uint16_t)state[2*i] << 8)  | state[2*i + 1];

        /* Need to put in the key `backwards` to make the indicies match later */
        t[i]     = ((uint16_t)key[14-2*i] << 8) | key[15-2*i];
        t[i + 4] = ((uint16_t)key[6-2*i]  << 8) | key[7-2*i];
    }

    /* Perform the encryption for the specified number of rounds */
    for (uint8_t round = 0; round < Rounds; round++) {
        uint16_t temp;

        /* Sbox, as described in Appendix C of the GIFT specification */
        s[1] ^= s[0] & s[2];
        s[0] ^= s[1] & s[3];
        s[2] ^= s[0] | s[1];
        s[3] ^= s[2];
        s[1] ^= s[3];
        s[3] ^= 0xffff; // Invert
        s[2] ^= s[0] & s[1];

        temp = s[0];
        s[0] = s[3];
        s[3] = temp;

        /* Permutation */
        s[0] = rowperm16(s[0], 0, 3, 2, 1);
        s[1] = rowperm16(s[1], 1, 0, 3, 2);
        s[2] = rowperm16(s[2], 2, 1, 0, 3);
        s[3] = rowperm16(s[3], 3, 2, 1, 0);

        /* Key addition */
        s[0] ^= t[1];
        s[1] ^= t[0];
        s[3] ^= 0x8000 ^ constants_space(1,0);

        /* Key State Update */
        uint16_t t0, t1;
        t0 = (t[0] << 4)  | (t[0] >> 12);
        t1 = (t[1] << 14) | (t[1] >> 2);

        for (uint8_t i = 2; i < 8; i++) {
            t[i - 2] = t[i];
        }
        t[7] = t1;
        t[6] = t0;
    }

    /* Copy output from state array */
    for (uint8_t i = 0; i < 4; i++) {
        state[2*i]     = s[i] >> 8;
        state[2*i + 1] = s[i];
    }

    return 0;
}

uint8_t
e128_slice(uint8_t* state, uint8_t* key, uint16_t Rounds)
{
    uint32_t s[4];  /* Cypherstate */
    uint16_t t[8];  /* Keystate */

    /* Copy input into state arrays */
    for (uint8_t i = 0; i < 4; i++){
        s[i] = ((uint32_t)state[4*i + 0] << 24) | ((uint32_t)state[4*i + 1] << 16)
             | ((uint32_t)state[4*i + 2] << 8)  | ((uint32_t)state[4*i + 3]);

        /* Need to put in the key `backwards` to make the indicies match later */
        t[i]     = ((uint16_t)key[14-2*i] << 8) | key[15-2*i];
        t[i + 4] = ((uint16_t)key[6-2*i]  << 8) | key[7-2*i];
    }

    /* Perform the encryption for the specified number of rounds */
    for (uint8_t round = 0; round < Rounds; round++) {
        uint32_t temp;

        /* Sbox, as described in Appendix C of the GIFT specification */
        s[1] ^= s[0] & s[2];
        s[0] ^= s[1] & s[3];
        s[2] ^= s[0] | s[1];
        s[3] ^= s[2];
        s[1] ^= s[3];
        s[3] ^= 0xffffffff; // Invert
        s[2] ^= s[0] & s[1];

        temp = s[0];
        s[0] = s[3];
        s[3] = temp;

        /* Permutation */
        s[0] = rowperm32(s[0], 0, 3, 2, 1);
        s[1] = rowperm32(s[1], 1, 0, 3, 2);
        s[2] = rowperm32(s[2], 2, 1, 0, 3);
        s[3] = rowperm32(s[3], 3, 2, 1, 0);

        /* Key addition */
        s[1] ^= ((uint32_t)t[1] << 16) | ((uint32_t)t[0]);
        s[2] ^= ((uint32_t)t[5] << 16) | ((uint32_t)t[4]);
        s[3] ^= 0x80000000 ^ constants_space(1,0);

        /* Key State Update */
        uint16_t t0, t1;
        t0 = (t[0] << 4)  | (t[0] >> 12);
        t1 = (t[1] << 14) | (t[1] >> 2);

        for (uint8_t i = 2; i < 8; i++) {
            t[i - 2] = t[i];
        }
        t[7] = t1;
        t[6] = t0;
    }

    /* Copy output from state array */
    for (uint8_t i = 0; i < 4; i++) {
        state[4*i]     = s[i] >> 24;
        state[4*i + 1] = s[i] >> 16;
        state[4*i + 2] = s[i] >> 8;
        state[4*i + 3] = s[i];
    }

    return 0;
}
