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
round_key64(const uint8_t* key_state, uint8_t round, uint8_t* k)
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
        round_key64((const uint8_t *)key, round, k);
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

//----------------------------------
// Decryption
//----------------------------------

uint64_t
decrypt(uint64_t in, uint64_t* subkey, uint16_t Rounds)
{
    return 0;
}

uint64_t*
decrypt128(uint64_t inHigh, uint64_t inLow, uint64_t* subkey, uint16_t Rounds)
{
    return 0;
}

// These decrypt and generate the key schedule on the fly, saving memory at the
// cost of more computations
uint64_t
decrypt_fly(uint64_t in, uint16_t Rounds)
{
    return 0;
}

uint64_t*
decrypt128_fly(uint64_t inHigh, uint64_t inLow, uint16_t Rounds)
{
    return 0;
}

//----------------------------------
// Key scheduling
//----------------------------------

uint64_t*
key_schedule(uint64_t key_high, uint64_t key_low, uint16_t Rounds)
{
    return 0;
}

uint64_t*
key_schedule128(uint64_t key_high, uint64_t key_low, uint16_t Rounds)
{
    return 0;
}
