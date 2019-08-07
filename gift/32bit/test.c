/**
 * This is an automated testbench wrapper to test the various encryption and
 * decryption functions for the 8-bit translation of PRESENT/GIFT
 *
 * Riley Myers (william.myers@inl.gov)
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "crypto.h"

// Known encryption results
const uint8_t PRESENT[8] = { 0xb3, 0xba, 0x73, 0xd0, 0x99, 0x0f, 0xbb, 0xd3 };
const uint8_t GIFT[8]    = { 0xa7, 0x8f, 0xe4, 0xee, 0x2b, 0x2e, 0x37, 0xbd };

void giftwrap(uint8_t P[16], const uint8_t K[16], uint8_t C[16]);

int
main(void)
{
    //uint8_t GIFT_KEY[16] = { 0x3c, 0x2f, 0xec, 0xdf, 0x34, 0x12, 0xab, 0xab,
    //                         0x21, 0x43, 0x65, 0x87, 0x78, 0x56, 0x34, 0x12 };
    uint8_t GIFT_KEY[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    //uint8_t TXT[8] = { 0x0d, 0xf0, 0xad, 0xeb, 0xfe, 0x0f, 0xdc, 0xba };
    //uint8_t TXT[16] = { 0x0d, 0xf0, 0xad, 0xeb, 0xfe, 0x0f, 0xdc, 0xba,
    //                    0x0d, 0xf0, 0xad, 0xeb, 0xfe, 0x0f, 0xdc, 0xba };
    uint8_t TXT[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    //encrypt_fly(TXT, GIFT_KEY, 28);
    //e128_slice(TXT, GIFT_KEY, 40);
    //e128_fly(TXT, GIFT_KEY, 40);
    //e64_fly(TXT, GIFT_KEY, 28);
    giftwrap(TXT, GIFT_KEY, TXT);

    //for (int i = 7; i >= 0; i--) { //For compatability with will's stuff?
    //for (int i = 0; i < 8; i++) {
    for (int i = 0; i < 16; i++) {
    //for (int i = 15; i >= 0; i--) {
        //assert(TXT[i] == GIFT[7 - i]);
        printf("%02hhx", TXT[i]);
    }
    printf("\n");

    return 0;
}


// wrapper function to make a non-bitslice version of a function work like the
//   bitslice variant

void
giftwrap(uint8_t P[16], const uint8_t K[16], uint8_t C[16])
{
    uint8_t T[16] = { 0 };

    // unpack the input from the bitslice input format
    for (uint8_t i = 0; i < 4; i++) {
        for (uint8_t j = 0; j < 2; j++) {
            for (int8_t k = 7; k >= 0; k--) {
                // printf("adding bit %03d [%d] from plaintext byte %d
                // [%02hhx]\n",
                //       (32 + i - 32 * j + 4 * k + 64), (P[4*i + j]>>k) & 0x1,
                //       4*i + j, P[4*i + j]);
                uint8_t shift = (32 + i - 32 * j + 4 * k);
                T[7 -  shift / 8] |= ((P[4 * i + j]     >> k) & 0x1) << (shift % 8);
                T[15 - shift / 8] |= ((P[4 * i + j + 2] >> k) & 0x1) << (shift % 8);

                //plain_h |= (uint64_t)((P[4 * i + j] >> k) & 0x1)
                //           << (shift);
                //plain_l |= (uint64_t)((P[4 * i + j + 2] >> k) & 0x1)
                //           << (shift);
            }
        }
    }

    uint8_t k[16];
    for (uint8_t i = 0; i < 16; i++) {
        k[i] = K[i];
    }
    for (uint8_t i = 0; i < 8; i++) {
        uint8_t tmp;
        uint8_t inv = 15 - i;
        tmp         = k[i];
        k[i]        = k[inv];
        k[inv]      = tmp;

        //tmp        = k[i + 8];
        //k[i + 8]   = k[inv + 8];
        //k[inv + 8] = tmp;
    }

    e128_fly(T, (uint8_t *)k, 40);

    // repack the output
    for (uint8_t i = 0; i < 4; i++) {
        for (uint8_t j = 0; j < 2; j++) {
            for (int8_t k = 7; k >= 0; k--) {
                uint8_t shift = (32 + i - 32 * j + 4 * k);
                C[4 * i + j]     |= ((T[7  - shift / 8] >> (shift % 8)) & 0x1) << k;
                C[4 * i + j + 2] |= ((T[15 - shift / 8] >> (shift % 8)) & 0x1) << k;
            }
        }
    }

    return;
}
