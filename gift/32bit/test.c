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
    uint8_t GIFT_KEY[16] = { 0x3c, 0x2f, 0xec, 0xdf, 0x34, 0x12, 0xab, 0xab,
                             0x21, 0x43, 0x65, 0x87, 0x78, 0x56, 0x34, 0x12 };
    //uint8_t GIFT_KEY[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    //                         0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    uint8_t TXT[8] = { 0x0d, 0xf0, 0xad, 0xeb, 0xfe, 0x0f, 0xdc, 0xba };
    //uint8_t TXT[16] = { 0x0d, 0xf0, 0xad, 0xeb, 0xfe, 0x0f, 0xdc, 0xba,
    //                    0x0d, 0xf0, 0xad, 0xeb, 0xfe, 0x0f, 0xdc, 0xba };
    //uint8_t TXT[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    //                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    //encrypt_fly(TXT, GIFT_KEY, 28);
    //e128_slice(TXT, GIFT_KEY, 40);
    e64_fly(TXT, GIFT_KEY, 28);

    for (int i = 7; i >= 0; i--) { //For compatability with will's stuff?
    //for (int i = 0; i < 8; i++) {
    //for (int i = 0; i < 16; i++) {
        //assert(TXT[i] == GIFT[7 - i]);
        printf("%02hhx", TXT[i]);
    }
    printf("\n");

    return 0;
}
