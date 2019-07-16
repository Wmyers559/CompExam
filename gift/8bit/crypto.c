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
// cost of more computations
uint8_t
encrypt_fly(uint8_t* state, uint8_t* key, uint16_t Rounds)
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
    uint8_t round;
    uint8_t save1;
    uint8_t save2;
    round = 0;

    do {
        //	****************** addRoundkey *************************
        i = 0;
        do {
            state[i] = state[i] ^ key[i + 2];
            i++;
        } while (i <= 7);
        //	****************** sBox ********************************
        do {
            i--;
            state[i] = Sbox[state[i] >> 4] << 4 | Sbox[state[i] & 0xF];
        } while (i > 0);
        //	****************** pLayer ******************************
        for (i = 0; i < 8; i++) // clearing of the temporary array temp_pLayer
        {
            temp_pLayer[i] = 0;
        }
        for (i = 0; i < 64; i++) {
            position = (16 * i) % 63; // arithmetic calculation of the
                                      // pLayer
            if (i == 63)              // exception for bit 63
                position = 63;
            element_source      = i / 8;
            bit_source          = i % 8;
            element_destination = position / 8;
            bit_destination     = position % 8;
            temp_pLayer[element_destination] |=
              ((state[element_source] >> bit_source) & 0x1) << bit_destination;
        }
        for (i = 0; i <= 7; i++) {
            state[i] = temp_pLayer[i];
        }
        //	****************** End pLayer **************************
        //	****************** Key Scheduling **********************
        //		on-the-fly key generation
        save1 = key[0];
        save2 = key[1];
        i     = 0;
        do {
            key[i] = key[i + 2];
            i++;
        } while (i < 8);
        key[8] = save1; // 61-bit left shift
        key[9] = save2;
        i      = 0;
        save1  = key[0] & 7;
        do {
            key[i] = key[i] >> 3 | key[i + 1] << 5;
            i++;
        } while (i < 9);
        key[9] = key[9] >> 3 | save1 << 5;

        key[9] = Sbox[key[9] >> 4] << 4 | (key[9] & 0xF); // S-Box application

        if ((round + 1) % 2 == 1) // round counter addition
            key[1] ^= 128;
        key[2] = ((((round + 1) >> 1) ^ (key[2] & 15)) | (key[2] & 240));
        //	****************** End Key Scheduling ******************
        round++;
    } while (round < Rounds);
    //	****************** addRoundkey *************************
    i = 0;
    do // final key XOR
    {
        state[i] = state[i] ^ key[i + 2];
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
