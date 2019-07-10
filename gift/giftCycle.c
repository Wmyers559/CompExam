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
#include "crypto.h"  // Crypto functions
#include "verbose.h" // For verbose output

//----------------------------------
// Start of code
//----------------------------------
int
main(int argc, char** const argv)
{
    // Initialize variables
    uint64_t       result;
    uint64_t*      result128 = NULL;
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
        uint64_t* subkey = NULL;
        if (Opt.BlockSize64) {

            if (Opt.Mode == Encrypt_Mode) {
                // Put out Values
                if (Opt.Verbose != 0) {
                    printf("Starting values\n");
                    printf("Plaintext: %016" PRIx64 " \n", Opt.Text);
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

                // Generate Subkeys
                subkey = key_schedule(Opt.KeyHigh,
                                      Opt.KeyLow,
                                      Opt.Rounds,
                                      Opt.KeySize80,
                                      (Opt.Verbose > 1));

                // Start Encryption
                if (Opt.Verbose != 0)
                    printf("Starting encryption...\n");
                result =
                  encrypt(Opt.Text, subkey, Opt.Rounds, (Opt.Verbose > 1));
                  long counter = 1;
                  int found = 0;
                  uint64_t cycleComp = result;
                  uint64_t newCycle = result;
                  while (found == 0)
                  {
                      newCycle = encrypt(newCycle, subkey, Opt.Rounds, (Opt.Verbose > 1));
                      if(newCycle == cycleComp)
                      {
                        printf("Cycle length %ld\n", counter);
                        found  = 1;
                      }
                      if (counter % 5000000 == 0)
                      {
                        printf("Index at: %ld\n", counter);
                      }
                      counter++;
                  }
                  return 0;
                  
                if (Opt.Verbose != 0)
                    printf("Resulting Cipher: %016" PRIx64 " \n\n", result);
                else
                    printf("%016" PRIx64 "\n", result);
            }

            else if (Opt.Mode == Decrypt_Mode) {
                // Put out Values
                if (Opt.Verbose != 0) {
                    printf("Starting values\n");
                    printf("Ciphertext: %016" PRIx64 " \n", Opt.Text);
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

                // Generate Subkeys
                subkey = key_schedule(Opt.KeyHigh,
                                      Opt.KeyLow,
                                      Opt.Rounds,
                                      Opt.KeySize80,
                                      (Opt.Verbose > 1));

                // Start Decryption
                if (Opt.Verbose != 0)
                    printf("Starting decryption...\n");
                result =
                  decrypt(Opt.Text, subkey, Opt.Rounds, (Opt.Verbose > 1));
                if (Opt.Verbose != 0)
                    printf("Resulting Plaintext: %016" PRIx64 " \n", result);
                else
                    printf("%016" PRIx64 "\n", result);
            }

            free(subkey);
        }

        else {

            subkey = key_schedule128(
              Opt.KeyHigh, Opt.KeyLow, Opt.Rounds, (Opt.Verbose > 1));

            // printf("128-bit option reached\n");

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
                result128 = encrypt128(Opt.TextHigh,
                                       Opt.Text,
                                       subkey,
                                       Opt.Rounds,
                                       (Opt.Verbose > 1));
                if (Opt.Verbose != 0)
                    printf("Resulting Cipher: %016" PRIx64 " %016" PRIx64
                           " \n\n",
                           result128[1],
                           result128[0]);
                else
                    printf("%016" PRIx64 " %016" PRIx64 "\n",
                           result128[1],
                           result128[0]);
            } else if (Opt.Mode == Decrypt_Mode) {

                if (Opt.Verbose != 0) {
                    printf("Starting values\n");
                    printf("CipherText: %016" PRIx64 " %016" PRIx64 " \n",
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
                    printf("Starting decryption...\n");
                result128 = decrypt128(Opt.TextHigh,
                                       Opt.Text,
                                       subkey,
                                       Opt.Rounds,
                                       (Opt.Verbose > 1));
                if (Opt.Verbose != 0)
                    printf("Resulting Plaintext: %016" PRIx64 " %016" PRIx64
                           " \n\n",
                           result128[1],
                           result128[0]);
                else
                    printf("%016" PRIx64 " %016" PRIx64 "\n",
                           result128[1],
                           result128[0]);
            }

            free(subkey);
            free(result128);
        }

    }

    else {
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
