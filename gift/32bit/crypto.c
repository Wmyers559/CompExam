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
 * value in `k`, which should point to an array of eight bytes to store the
 * round key in.
 */

uint8_t
round_key64(const uint8_t* key_state, uint8_t* k)
{
    uint8_t i;
    uint8_t u[2] = { 0 };
    uint8_t v[2] = { 0 };

    // V = k_0 , U = k_1 (16 bit words)
    v[0] = key_state[0];
    v[1] = key_state[1];
    u[0] = key_state[2];
    u[1] = key_state[3];

    // zero out previous round key
    for (i = 0; i < 8; i++) {
        k[i] = 0;
    }

    // introduce keystate to the round key
    for (i = 0; i < 16; i++) {
        uint8_t j = 4 * i;
        k[j / 8] |= ((v[i / 8] >> (i % 8)) & 0x1) << (j % 8);
        k[(j + 1) / 8] |= ((u[i / 8] >> (i % 8)) & 0x1) << ((j + 1) % 8);
    }

    // Add in constants
    for (uint8_t c = constants_space(True, False), i = 0; i < 6; i++) {
        // Constants are inserted at bit positions 23, 19, 15, 11, 7, 3
        uint8_t j = 3 + 4 * i;
        k[j / 8] |= ((c >> i) & 0x1) << (j % 8);
    }

    // unconditionally set the upper bit on the round key
    k[7] |= 0x80;

    return 0;
}

uint8_t
round_key128(const uint8_t* key_state, uint8_t* k)
{
    uint8_t i;
    uint8_t u[4] = { 0 };
    uint8_t v[4] = { 0 };

    // V = k_1 || k_0 , U = k_5 || k_4 (16 bit words)
    v[0] = key_state[0];
    v[1] = key_state[1];
    v[2] = key_state[2];
    v[3] = key_state[3];

    u[0] = key_state[8];
    u[1] = key_state[9];
    u[2] = key_state[10];
    u[3] = key_state[11];

    // zero out previous round key
    for (i = 0; i < 16; i++) {
        k[i] = 0;
    }

    // introduce keystate to the round key
    for (i = 0; i < 32; i++) {
        uint8_t j = 4 * i + 1;
        k[j / 8] |= ((v[i / 8] >> (i % 8)) & 0x1) << (j % 8);
        k[(j + 1) / 8] |= ((u[i / 8] >> (i % 8)) & 0x1) << ((j + 1) % 8);
    }

    // Add in constants
    for (uint8_t c = constants_space(True, False), i = 0; i < 6; i++) {
        // Constants are inserted at bit positions 23, 19, 15, 11, 7, 3
        uint8_t j = 3 + 4 * i;
        k[j / 8] |= ((c >> i) & 0x1) << (j % 8);
    }

    // unconditionally set the upper bit on the round key
    k[15] |= 0x80;

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
// cost of more computations. This does mangle the key and plaintext passed in:
// the result of the encryption is returned in-place, and the key is used to
// calculate the key_state
uint8_t
encrypt_fly(uint8_t* text, uint8_t* key, uint16_t Rounds)
{
    //	Counter
    uint8_t i = 0;
    //	pLayer variables
    uint8_t position            = 0;
    uint8_t element_source      = 0;
    uint8_t bit_source          = 0;
    uint8_t element_destination = 0;
    uint8_t bit_destination     = 0;
    uint8_t temp_pLayer[8];
    //	Key scheduling variables
    uint8_t rot[4] = { 0 };
    uint8_t round  = 0;

    uint8_t k[8] = { 0 };

    do {
        //	****************** sBox ********************************
        i = 8;
        do {
            i--;
            text[i] = Sbox[text[i] >> 4] << 4 | Sbox[text[i] & 0xF];
        } while (i > 0);
        //	****************** pLayer ******************************
        for (i = 0; i < 8; i++) {
            temp_pLayer[i] = 0; // clearing of the temporary array temp_pLayer
        }
        for (i = 0; i < 64; i++) {
            // Ok then...
            position = 4 * (i / 16) +
                       16 * ((3 * ((i % 16) / 4) + (i % 4)) % 4) + (i % 4);

            // To retain exact compatability with William Unger's version, this
            // also treats the MSB as bit 0 and goes from there :|
            element_source      = (63 - position) / 8;
            bit_source          = (63 - position) % 8;
            element_destination = (63 - i) / 8;
            bit_destination     = (63 - i) % 8;
            temp_pLayer[element_destination] |=
              ((text[element_source] >> bit_source) & 0x1) << bit_destination;
        }
        for (i = 0; i <= 7; i++) {
            text[i] = temp_pLayer[i];
        }
        //	****************** End pLayer **************************

        //	****************** addRoundkey *************************
        round_key64((const uint8_t *)key, k);
        i = 0;
        do {
            text[i] = text[i] ^ k[i];
            i++;
        } while (i < 8);

        //	****************** Key Scheduling **********************
        //		on-the-fly key generation
        rot[0] = key[0];
        rot[1] = key[1];
        rot[2] = key[2];
        rot[3] = key[3];
        i      = 0;
        do {
            key[i] = key[i + 4];
            i++;
        } while (i < 12);

        key[12] = (rot[1] >> 4) | (rot[0] << 4);
        key[13] = (rot[0] >> 4) | (rot[1] << 4);
        key[14] = (rot[2] >> 2) | (rot[3] << 6);
        key[15] = (rot[3] >> 2) | (rot[2] << 6);

        //	****************** End Key Scheduling ******************
        round++;
    } while (round < Rounds);

    return 0;
}

uint8_t
encrypt128_fly(uint8_t* text, uint8_t* key, uint16_t Rounds)
{
    //	Counter
    uint8_t i = 0;
    //	p variables
    uint8_t position  = 0;
    uint8_t elem_src  = 0;
    uint8_t bit_src   = 0;
    uint8_t elem_dest = 0;
    uint8_t bit_dest  = 0;
    uint8_t p_buf[16];
    //	Key scheduling variables
    uint8_t k[16]  = { 0 }; // Round key
    uint8_t rot[4] = { 0 };

    uint8_t round  = 0;


    for (round = 0; round < Rounds; round++ ) {

        //	****************** sBox ********************************
        for ( i = 0; i < 16; i++) {
            text[i] = Sbox[text[i] >> 4] << 4 | Sbox[text[i] & 0xF];
        }

        //	****************** pLayer ******************************
        for (i = 0; i < 16; i++) {
            p_buf[i] = 0;
        }

        for (i = 0; i < 128; i++) {
            // Ok then...
            position = 4 * (i / 16) +
                       32 * ((3 * ((i % 16) / 4) + (i % 4)) % 4) + (i % 4);

            elem_src          = (i) / 8;
            bit_src           = (i) % 8;
            elem_dest         = (position) / 8;
            bit_dest          = (position) % 8;
            p_buf[elem_dest] |= ((text[elem_src] >> bit_src) & 0x1) << bit_dest;
        }

        for (i = 0; i < 16; i++) {
            text[i] = p_buf[i];
        }

        //	****************** addRoundkey *************************
        round_key128((const uint8_t *)key, k);
        for (i = 0; i < 16; i++) {
            text[i] = text[i] ^ k[i];
        }

        //	****************** Key Scheduling **********************
        //		on-the-fly key generation
        rot[0] = key[0];
        rot[1] = key[1];
        rot[2] = key[2];
        rot[3] = key[3];

        for (i = 0; i < 12; i++) {
            key[i] = key[i + 4];
        }

        key[12] = (rot[1] >> 4) | (rot[0] << 4);
        key[13] = (rot[0] >> 4) | (rot[1] << 4);
        key[14] = (rot[2] >> 2) | (rot[3] << 6);
        key[15] = (rot[3] >> 2) | (rot[2] << 6);

    }

    return 0;
}


// These use an efficient bit-slice implementation of the algorithm, mirroring
// the reference implementation in the GIFT-COFB NIST submission
uint8_t
e64_slice(uint8_t* state, uint8_t* key, uint16_t Rounds)
{
    uint16_t s[4];
    uint16_t t[8]; 

    for (uint8_t i = 0; i < 4; i++){
        s[i]     = ((uint16_t)state[2*i] << 8)     | state[2*i + 1];
        t[i]     = ((uint16_t)key[2*i] << 8)       | key[2*i + 1];
        t[i + 4] = ((uint16_t)key[2*(i + 4)] << 8) | key[2*(i + 4) + 1];
    } 

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
    
    for (uint8_t i = 0; i < 4; i++) { 
        state[2*i]      = s[i] >> 8;
        state[2*i + 1] = s[i];
    }

    return 0;
}

uint8_t
e128_slice(uint8_t* state, uint8_t* key, uint16_t Rounds)
{
    return 0;
}
