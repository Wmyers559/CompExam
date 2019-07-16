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
const uint8_t GIFT[8]    = { 0 };

int
main(void)
{
    uint8_t PRESENT_KEY[10] = { 0x00, 0x11, 0x22, 0x33, 0x44,
                                0x55, 0x66, 0x77, 0x88, 0x99 };
    uint8_t TXT[8] = { 0xba, 0xdc, 0x0f, 0xfe, 0xeb, 0xad, 0xf0, 0x0d };
    // TODO

    encrypt_fly(TXT, PRESENT_KEY, 31);

    for (int i = 0; i < 8; i++) {
        assert(TXT[i] == PRESENT[i]);
        printf("%02hhx", TXT[i]);
    }
    printf("\n");

    return 0;
}
