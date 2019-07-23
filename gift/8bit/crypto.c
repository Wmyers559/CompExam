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
round_key64(uint8_t* key_state, uint8_t round, uint8_t* k)
{
    uint8_t i;
    uint8_t u[2] = { 0 };
    uint8_t v[2] = { 0 };

    // V = k_0 , U = k_1 (16 bit words)
    v[0] = key_state[0];
    v[1] = key_state[1];
    u[0] = key_state[2];
    u[1] = key_state[3];

    // introduce keystate to the round key
    for (i = 0; i < 8; i++) {
        uint8_t j = 4 * i;
        k[j / 8] |= ((v[0] >> i) & 0x1) << (j % 8);
        k[(j + 1) / 8] |= ((u[0] >> i) & 0x1) << ((j + 1) % 8);
        j <<= 1;
        k[j / 8] |= ((v[1] >> i) & 0x1) << (j % 8);
        k[(j + 1) / 8] |= ((u[1] >> i) & 0x1) << ((j + 1) % 8);
    }

    // Add in constants
    for (uint8_t c = constants_time(round), i = 0; i < 6; i++) {
        // Constants are inserted at bit positions 23, 19, 15, 11, 7, 3
        uint8_t j = 3 + 4 * i;
        k[j / 8] |= ((c >> i) & 0x1) << (j % 8);
    }

    // unconditionally set the upper bit on the round key
    k[7] |= 0x80;

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
        round_key64(key, round, k);

        //	****************** addRoundkey *************************
        i = 0;
        do {
            text[i] = text[i] ^ k[i];
            i++;
        } while (i <= 7);
        //	****************** sBox ********************************
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

            element_source      = i / 8;
            bit_source          = i % 8;
            element_destination = position / 8;
            bit_destination     = position % 8;
            temp_pLayer[element_destination] |=
              ((text[element_source] >> bit_source) & 0x1) << bit_destination;
        }
        for (i = 0; i <= 7; i++) {
            text[i] = temp_pLayer[i];
        }
        //	****************** End pLayer **************************

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

    //	****************** addRoundkey *************************
    round_key64(key, round, k);
    i = 0;
    do { // final key XOR
        text[i] = text[i] ^ k[i];
        i++;
    } while (i <= 7);

    return 0;
}

uint8_t
encrypt128_fly(uint8_t* state, uint8_t* key, uint16_t Rounds)
{
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
