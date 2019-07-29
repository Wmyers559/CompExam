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
#include "gift128.h"  // Crypto functions
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

    // Banner
    if (Opt.Verbose != 0) {
        printf("---------------------------------------\n");
        printf("PRESENT Commandline Tool v2.1\n");
        printf("Thomas Siebert, thomas.siebert@rub.de\n");
        printf("Edited to GIFT Commandline Tool v1.0\n");
        printf("William Unger, williamunger@u.boisesate.edu\n");
        printf("---------------------------------------\n\n");
    }

    if (!Opt.Error) {
        if (Opt.BlockSize64) {
        } else {


            if (Opt.Mode == Encrypt_Mode) {
                // printf("Encypt mode 128-bit block reached.\n");

                if (Opt.Verbose != 0) {
                    printf("Starting values\n");
                    printf("Plaintext: %016" PRIx64 " %016" PRIx64 " \n",
                           Opt.TextHigh,
                           Opt.Text);
                    if (Opt.KeySize80)
                        printf("Given Key (80bit): %016" PRIx64 " %04" PRIx64
                               "\n\n",
                               Opt.KeyHigh,
                               (Opt.KeyLow & 0xFFFF));
                    else
                        printf("Given Key (128bit): %016" PRIx64 " %016" PRIx64
                               "\n\n",
                               Opt.KeyHigh,
                               Opt.KeyLow);
                }

                if (Opt.Verbose != 0)
                    printf("Starting encryption...\n");

                uint8_t txt[16];
                uint8_t key[16];
                uint8_t result[16];
                *(uint64_t *)txt       = Opt.Text;
                *(uint64_t *)(txt + 8) = Opt.TextHigh;
                *(uint64_t *)key       = Opt.KeyLow;
                *(uint64_t *)(key + 8) = Opt.KeyHigh;

                //giftb128(txt, key, result);
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

                for (uint8_t i = 0; i < 8; i++) {
                    uint8_t t = key[i];
                    key[i] = key[15 - i];
                    key[15 - i] = t;

                    t = txt[i];
                    txt[i] = txt[15 - i];
                    txt[15 - i] = t;
                }

                //giftb128(txt, key, result);
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

            }
        }

    } else {
        // Put out Syntax
        printf("Syntax:\n");
        printf("PRESENT -d|e [-f] [-r rounds] [-v level] -k key -t text\n\n");
        printf("Choose -d to decrypt, or -e to encrypt one block\n\n");
        printf("-f (optional): File input, see below\n");
        printf("-r rounds (optional): Change number of rounds (up to 65534, "
               "standard is 32)\n");
        printf("-v level (optional): Specify verbose level:\n");
        printf("   0 for result-output only\n");
        printf("   1 for output of mode, input, result (standard)\n");
        printf("   2 for roundwise output\n\n");
        printf("-k key: Key in hexadecimal (length: *EXACTLY* 20 "
               "chars(80bit)/32 chars(128bit))\n");
        printf("-t text: Text in hexadecimal (length: *EXACTLY* 16 chars)\n");
        printf("If -f is set, key and text represent files containing the "
               "values,\n");
        printf("otherwise they must be passed directly via commandline.\n\n");
        printf("Returned Errorlevel: 0 if successful, 1 if non-successful\n");
    }
    return Opt.Error;
}
