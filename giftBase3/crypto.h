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
    0x00, 0x11, 0x22, 0x44, 0x55, 0x66, 0x88, 0x99, \
    0xaa, 0x01, 0x24, 0x56, 0x89, 0xa0, 0x12, 0x45}

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

uint64_t
base3Add(uint64_t in, 
         uint64_t subkey);

uint64_t
base3Invert(uint64_t in);
