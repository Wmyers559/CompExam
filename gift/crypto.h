/**
 * Implementation of GIFT in C, cryptographic core functions
 *
 * Thomas Siebert, thomas.siebert@rub.de
 * William Unger, williamunger@u.boisestate.edu
 *
 * Modified and modularized by Riley Myers (william.myers@inl.gov)
 *
 */

#pragma once
#include <stdint.h>

#define KEY_LENGTH 16
#define DEFAULT_KEY {                               \
    0x12, 0x34, 0x56, 0x78, 0x87, 0x65, 0x43, 0x21, \
    0xab, 0xab, 0x12, 0x34, 0xdf, 0xec, 0x2f, 0x3c} 

//----------------------------------
// Function prototypes
//----------------------------------
uint64_t
encrypt(uint64_t in, uint64_t* subkey, uint16_t Rounds, _Bool Roundwise);

uint64_t*
encrypt128(uint64_t  inHigh,
           uint64_t  inLow,
           uint64_t* subkey,
           uint16_t  Rounds,
           _Bool     Roundwise);

uint64_t
decrypt(uint64_t in, uint64_t* subkey, uint16_t Rounds, _Bool Roundwise);

uint64_t*
decrypt128(uint64_t  inHigh,
           uint64_t  inLow,
           uint64_t* subkey,
           uint16_t  Rounds,
           _Bool     Roundwise);


uint64_t*
key_schedule(uint64_t key_high,
             uint64_t key_low,
             uint16_t Rounds,
             _Bool    KeySize80,
             _Bool    Output);
uint64_t*
key_schedule128(uint64_t key_high,
                uint64_t key_low,
                uint16_t Rounds,
                _Bool    Output);
