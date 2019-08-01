/*
 * Implementation of PRESENT in C
 * v2.1, 10/13/2008
 * Edited to GIFT
 *
 * Thomas Siebert, thomas.siebert@rub.de
 *
 * William Unger, williamunger@u.boisestate.edu
 *
 * Modified and modularized by Riley Myers (william.myers@inl.gov)
 *
 *
 * Your Compiler currently should support
 * the ANSI-C99-standard.
 *
 * Tested with gcc (with Option -std=c99)
 */

//----------------------------------
// Includes
//----------------------------------
#include <getopt.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h> //Standard C headers...
#include <stdlib.h>

#include "comline.h" // Command Line
#include "gift128.h" // Crypto functions
#include "verbose.h" // For verbose output

//----------------------------------
// Start of code
//----------------------------------
int
main(int argc, char** const argv)
{
    // Initialize variables
    struct Options Opt;

    // Get Commandline Options
    comline_fetch_options(&Opt, argc, argv);

    uint8_t txt[16]    = { 0 };
    uint8_t key[16]    = { 0 };
    uint8_t result[16] = { 0 };

    // Hacky!
    *(uint64_t*)txt       = Opt.Text;
    *(uint64_t*)(txt + 8) = Opt.TextHigh;
    *(uint64_t*)key       = Opt.KeyLow;
    *(uint64_t*)(key + 8) = Opt.KeyHigh;

    /*
    if (!Opt.Mode)
        giftb128(txt, key, result);
    else
        giftwrap(txt, key, result);

    for (uint8_t i = 0; i < 16; i++) {
        printf("%02hhx", result[15 - i]);
    }
    printf("\n");
    printf("\n");
    for (uint8_t i = 0; i < 16; i++) {
        printf("%02hhx", result[i]);
    }
    printf("\n");
    printf("--------------------\n");
    */

    for (uint8_t i = 0; i < 8; i++) {
        uint8_t t   = key[i];
        key[i]      = key[15 - i];
        key[15 - i] = t;

        t           = txt[i];
        txt[i]      = txt[15 - i];
        txt[15 - i] = t;
    }

    if (!Opt.Mode)
        giftb128(txt, key, result);
    else
        giftwrap(txt, key, result);

    /*
    for (uint8_t i = 0; i < 16; i++) {
        printf("%02hhx", result[15 - i]);
    }
    printf("\n");
    printf("\n");
    */
    for (uint8_t i = 0; i < 16; i++) {
        printf("%02hhx", result[i]);
    }
    printf("\n");

    return Opt.Error;
}
