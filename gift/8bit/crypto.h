/**
 * Implementation of GIFT in C, cryptographic core functions
 *
 * Dirk Klose
 * Riley Myers (william.myers@inl.gov)
 *
 */

#pragma once
#include <stdint.h>

#define KEY_LENGTH 16
#define DEFAULT_KEY                                                            \
    {                                                                          \
        0x12, 0x34, 0x56, 0x78, 0x87, 0x65, 0x43, 0x21, 0xab, 0xab, 0x12,      \
          0x34, 0xdf, 0xec, 0x2f, 0x3c                                         \
    }

//----------------------------------
// Function prototypes
//----------------------------------

//----------------------------------
// Encryption
//----------------------------------
// All of these functions take the plaintext as the first argument, and modify
// it in-place.

// These encrypt the plaintext using a pregenerated subkey array, optimizing for
// speed (TODO!)
uint8_t
encrypt(uint64_t in, uint64_t* subkey, uint16_t Rounds);

uint8_t
encrypt128(uint64_t inHigh, uint64_t inLow, uint64_t* subkey, uint16_t Rounds);

// These encrypt and generate the key schedule on the fly, saving memory at the
// cost of more computations
uint8_t
encrypt_fly(uint8_t* state, uint8_t* key, uint16_t Rounds);

uint8_t
encrypt128_fly(uint8_t* state, uint8_t* key, uint16_t Rounds);

//----------------------------------
// Decryption (TODO)
//----------------------------------

uint64_t
decrypt(uint64_t in, uint64_t* subkey, uint16_t Rounds);

uint64_t*
decrypt128(uint64_t inHigh, uint64_t inLow, uint64_t* subkey, uint16_t Rounds);

// These decrypt and generate the key schedule on the fly, saving memory at the
// cost of more computations
uint64_t
decrypt_fly(uint64_t in, uint16_t Rounds);

uint64_t*
decrypt128_fly(uint64_t inHigh, uint64_t inLow, uint16_t Rounds);

//----------------------------------
// Key scheduling (TODO)
//----------------------------------

uint64_t*
key_schedule(uint64_t key_high, uint64_t key_low, uint16_t Rounds);

uint64_t*
key_schedule128(uint64_t key_high, uint64_t key_low, uint16_t Rounds);
