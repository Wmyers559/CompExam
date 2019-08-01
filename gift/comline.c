/*
 * Commandline-Option-Fetcher for
 * Implementation of PRESENT in C
 * v2.1, 10/13/2008
 *
 * Thomas Siebert, thomas.siebert@rub.de
 *
 * Modified and modularized by Riley Myers (william.myers@inl.gov)
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <getopt.h>
#include <unistd.h>

#include "comline.h"

//----------------------------------
// Functions
//----------------------------------
void
comline_fetch_options(struct Options* sOpt, int argc, char** const argv)
{
    int   c;
    _Bool Opt_Decrypt = 0, Opt_Encrypt = 0, Opt_File = 0, Opt_Verbose = 0;
    char *Opt_Text = NULL, *Opt_Key = NULL, *Opt_Rounds = NULL;
    FILE *KeyFile = NULL, *TextFile = NULL;

    sOpt->Error       = 0;
    sOpt->Verbose     = 1;
    sOpt->BlockSize64 = 1;

    // Process the command line options
    while ((c = getopt(argc, argv, "defv:r:k:t:")) != -1) {
        switch (c) {
            case 'd':
                if (Opt_Encrypt || Opt_Decrypt)
                    sOpt->Error = 1;
                else
                    Opt_Decrypt = 1;
                break;
            case 'e':
                if (Opt_Encrypt || Opt_Decrypt)
                    sOpt->Error = 1;
                else
                    Opt_Encrypt = 1;
                break;
            case 'f':
                if (Opt_File)
                    sOpt->Error = 1;
                else
                    Opt_File = 1;
                break;
            case 'v':
                if (Opt_Verbose)
                    sOpt->Error = 1;
                else if (optarg != NULL) {
                    if (strcmp(optarg, "0") == 0)
                        sOpt->Verbose = 0;
                    else if (strcmp(optarg, "1") == 0)
                        sOpt->Verbose = 1;
                    else if (strcmp(optarg, "2") == 0)
                        sOpt->Verbose = 2;
                    else
                        sOpt->Error = 1;
                } else
                    sOpt->Error = 1;
                Opt_Verbose = 1;
                break;
            case 'k':
                if (Opt_Key != NULL)
                    sOpt->Error = 1;
                else
                    Opt_Key = optarg;
                break;
            case 'r':
                if (Opt_Rounds)
                    sOpt->Error = 1;
                else
                    Opt_Rounds = optarg;
                break;
            case 't':
                if (Opt_Text != NULL)
                    sOpt->Error = 1;
                else
                    Opt_Text = optarg;
                break;
            case '?':
                sOpt->Error = 1;
                break;
        }
    }
    // Finished parsing command-line options

    // Set Error if Parameters missing
    if (Opt_Key == NULL || Opt_Text == NULL ||
        (!(Opt_Decrypt || Opt_Encrypt))) {
        sOpt->Error = 1;

    } else {

        if (Opt_File) {
            KeyFile  = fopen(Opt_Key, "r");
            TextFile = fopen(Opt_Text, "r");

            if (!((KeyFile == NULL) || (TextFile) == NULL)) {
                fseek(KeyFile, 0, SEEK_END);

                if ((ftell(KeyFile)) >= 32) {
                    fseek(KeyFile, 0, SEEK_SET);
                    if (fscanf(KeyFile, "%016" SCNx64 "", &sOpt->KeyHigh) == 0)
                        sOpt->Error = 1;
                    if (fscanf(KeyFile, "%016" SCNx64 "", &sOpt->KeyLow) == 0)
                        sOpt->Error = 1;
                    sOpt->KeySize80 = 0;

                } else if ((ftell(KeyFile)) >= 20) {
                    fseek(KeyFile, 0, SEEK_SET);
                    if (fscanf(KeyFile, "%016" SCNx64 "", &sOpt->KeyHigh) == 0)
                        sOpt->Error = 1;
                    if (fscanf(KeyFile,
                               "%04" SCNx16 "",
                               (uint16_t*)&sOpt->KeyLow) == 0)
                        sOpt->Error = 1;
                    sOpt->KeySize80 = 1;
                } else {
                    sOpt->Error = 1;
                }

                fseek(TextFile, 0, SEEK_END);
                if ((ftell(TextFile)) >= 32) {
                    fseek(TextFile, 0, SEEK_SET);
                    // printf("reading in 128-bits\n");
                    if (fscanf(TextFile, "%016" SCNx64 "", &sOpt->TextHigh) ==
                        0)
                        sOpt->Error = 1;
                    if (fscanf(TextFile, "%016" SCNx64 "", &sOpt->Text) == 0)
                        sOpt->Error = 1;
                    sOpt->BlockSize64 = 0;

                } else {
                    // printf("reading in 64-bits\n");
                    fseek(TextFile, 0, SEEK_SET);
                    if (fscanf(TextFile, "%016" SCNx64 "", &sOpt->Text) == EOF)
                        sOpt->Error = 1;
                    sOpt->BlockSize64 = 1;
                }
            } else {
                sOpt->Error = 1;
            }

            if (!(KeyFile == NULL))
                fclose(KeyFile);
            if (!(TextFile == NULL))
                fclose(TextFile);

            // Read key and text (commandline mode)
        } else {

            // If any entry is the wrong length, note that an error occured
            if (((strlen(Opt_Key) != 32)) ||
                ((strlen(Opt_Text) != 16) && (strlen(Opt_Text) != 32))) {
                sOpt->Error = 1;
            }

            // If there was no error,
            if (!(sOpt->Error)) {
                sscanf(Opt_Key, "%016" SCNx64 "", &sOpt->KeyHigh); // get values
                if (strlen(Opt_Key) == 20) { // set key + size
                    sOpt->KeySize80 = 1;
                    sscanf(
                      Opt_Key + 16, "%016" SCNx16 "", (uint16_t*)&sOpt->KeyLow);

                } else {
                    sOpt->KeySize80 = 0;
                    sscanf(Opt_Key + 16, "%016" SCNx64 "", &sOpt->KeyLow);
                }

                if (strlen(Opt_Text) == 16) {
                    sscanf(Opt_Text, "%016" SCNx64 "", &sOpt->Text);
                } else {
                    sscanf(Opt_Text, "%016" SCNx64 "", &sOpt->TextHigh);
                    sscanf(Opt_Text + 16, "%016" SCNx64 "", &sOpt->Text);
                    sOpt->BlockSize64 = 0;
                }
            }
        }
        // Handle Rounds Parameter
        if (Opt_Rounds != NULL) {         // if Round Param there...
            if (strlen(Opt_Rounds) < 6) { // check length
                uint32_t Rounds;
                sscanf(Opt_Rounds, "%5" SCNu32 "", &Rounds); // get round no.
                if ((Rounds > 47) || Rounds == 0) // check 0 < Rounds < 48
                    sOpt->Error = 1;
                else
                    sOpt->Rounds = Rounds;

            } else {
                sOpt->Error = 1;
            }

            // or use the standard parameters
        } else if (sOpt->BlockSize64) {
            sOpt->Rounds = 29;
        } else {
            sOpt->Rounds = 41;
        }

        // Check if decrypt or encrypt mode
        if (Opt_Encrypt)
            sOpt->Mode = Encrypt_Mode;
        else
            sOpt->Mode = Decrypt_Mode;

        // Read key and text (file mode)make
    }
}
