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

int
main(void)
{
    //uint8_t PRESENT_KEY[10] = { 0x00, 0x11, 0x22, 0x33, 0x44,
    //                            0x55, 0x66, 0x77, 0x88, 0x99 };
    //uint8_t GIFT_KEY[16] = { 0x12, 0x34, 0x56, 0x78, 0x87, 0x65, 0x43, 0x21,
    //                         0xab, 0xab, 0x12, 0x34, 0xdf, 0xec, 0x2f, 0x3c };
    //uint8_t GIFT_KEY[16] = { 0x21, 0x43, 0x65, 0x87, 0x78, 0x45, 0x34, 0x12,
    //                         0x3c, 0x2f, 0xec, 0xdf, 0x34, 0x12, 0xab, 0xab };
    uint8_t GIFT_KEY[16] = { 0x3c, 0x2f, 0xec, 0xdf, 0x34, 0x12, 0xab, 0xab,
                             0x21, 0x43, 0x65, 0x87, 0x78, 0x45, 0x34, 0x12 };
    //uint8_t TXT[8] = { 0xba, 0xdc, 0x0f, 0xfe, 0xeb, 0xad, 0xf0, 0x0d };
    uint8_t TXT[8] = { 0x0d, 0xf0, 0xad, 0xeb, 0xfe, 0x0f, 0xdc, 0xba };
    // TODO

    encrypt_fly(TXT, GIFT_KEY, 31);

    for (int i = 0; i < 8; i++) {
        //assert(TXT[i] == GIFT[i]);
        printf("%02hhx", TXT[i]);
    }
    printf("\n");

    return 0;
}