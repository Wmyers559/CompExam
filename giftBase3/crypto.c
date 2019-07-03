/**
 * Implementation of GIFT in C, cryptographic core functions
 *
 * Thomas Siebert, thomas.siebert@rub.de
 * William Unger, williamunger@u.boisestate.edu
 *
 * Modified and modularized by Riley Myers (william.myers@inl.gov)
 *
 */

#include "crypto.h"
#include "bits.h"
#include "boxes.h"
//#include "verbose.h" // For verbose output

#include <stdio.h>
#include <stdlib.h>

//----------------------------------
// Key Scheduling
//----------------------------------
uint64_t*
key_schedule(uint64_t key_high,
             uint64_t key_low,
             uint16_t Rounds,
             _Bool    KeySize80,
             _Bool    Output)
{
    //uint64_t temp64;
    uint64_t i;

    uint64_t* subkey = (uint64_t*)malloc(Rounds * sizeof(uint64_t));

    if (subkey != NULL) {

        if (KeySize80) {
            // no stdlib
        } else { // 128 Bit

            uint16_t keyState[8];
            for (i = 0; i < 4; i++) {

                // Initlize 128 bit key into 8 16-bit keystates
                keyState[i] = ((key_low >> (i * 16)) & 0xffff);
                keyState[i + 4] = ((key_high >> (i * 16)) & 0xffff);
            }

            for (i = 0; i < Rounds; i++) {
                subkey[i]              = 0;
                uint16_t U             = keyState[1];
                uint16_t V             = keyState[0];
                //uint8_t  roundConstant = Constants[i];

                // printf("U in round %i value: %i\n", i, U);
                // printf("V in round %i value: %i\n", i, V);

                int j;
                for (j = 0; j < 8; j++) {
                    // Putting keystate into the subkey
                    subkey[i] = setBit(subkey[i], getBit(U, (2*j +1)), (4 * j + 1));
                    subkey[i] = setBit(subkey[i], getBit(U, (2*j)), (4 * j));
                }
                for (j = 8; j < 16; j++) {
                    // Putting keystate into the subkey
                    subkey[i] = setBit(subkey[i], getBit(V, (2*(j-8) + 1)), (4 * j + 1));
                    subkey[i] = setBit(subkey[i], getBit(V, (2*(j-8))), (4 * j));
                }
                // printf("Constant for round %i value :%i\n",i,Constants[i]);

                /*
                for (j = 0; j < 6; j++) {
                    subkey[i] = setBit(
                      subkey[i], getBit(Constants[i], j), ConstantsLocation[j]);
                    // The addition of the round constants of the round key
                }

                // always having 1 on the blockSize-1 round key
                subkey[i] = setBit(subkey[i], 0x01, 63);
                */

                // below is the update of the key state.
                uint16_t keyStateUpdated[8];
                keyStateUpdated[7] = rotateRight16Bit(keyState[1], 2);
                keyStateUpdated[6] = rotateRight16Bit(keyState[0], 12);
                keyStateUpdated[5] = keyState[7];
                keyStateUpdated[4] = keyState[6];
                keyStateUpdated[3] = keyState[5];
                keyStateUpdated[2] = keyState[4];
                keyStateUpdated[1] = keyState[3];
                keyStateUpdated[0] = keyState[2];

                for (j = 0; j < 8; j++) {
                    keyState[j] = keyStateUpdated[j];
                }
            }
        }
    } else {
        // No stdlib
    }
    return subkey;
}

uint64_t*
key_schedule128(uint64_t key_high,
                uint64_t key_low,
                uint16_t Rounds,
                _Bool    Output)
{
    //uint64_t temp64;
    uint64_t i;

    uint64_t* subkey = (uint64_t*)malloc(Rounds * 2 * sizeof(uint64_t));
    uint16_t  keyState[8];

    for (i = 0; i < 4; i++) {
        // Initlize 128 bit key into 8 16-bit keystates
        keyState[i] = ((key_low >> (i * 16)) & 0xffff);
        keyState[i + 4] = ((key_high >> (i * 16)) & 0xffff);
    }
    for (i = 0; i < Rounds; i++) {
        subkey[2 * i]          = 0;
        subkey[(2 * i) + 1]    = 0;
        uint32_t U             = 0;
        uint32_t V             = 0;
        //uint8_t  roundConstant = Constants[i];

        U = ((uint32_t)keyState[5] << 16) | (uint32_t)(keyState[4]);
        V = ((uint32_t)keyState[1] << 16) | (uint32_t)(keyState[0]);

        int j;

        for (j = 0; j < 8; j++) {
            
            subkey[2 * i] = setBit(subkey[2 * i], getBit(U, (2*j +1)), (4 * j + 1));
            subkey[2 * i] = setBit(subkey[2 * i], getBit(U, (j*2)), (4 * j));
            // Putting keystate into the subkey
            subkey[2 * i + 1] =
              setBit(subkey[2 * i + 1], getBit(U, ((2*j) + 1 + 16)), (4 * j + 1));
            subkey[2 * i + 1] =
              setBit(subkey[2 * i + 1], getBit(U, ((2*j) + 16)), (4 * j));
        }
        for (j = 8; j < 16; j++)
        {                    
            subkey[2 * i] = setBit(subkey[2 * i], getBit(V, (2*(j-8) +1)), (4 * j + 1));
            subkey[2 * i] = setBit(subkey[2 * i], getBit(V, (2*(j-8))), (4 * j));
            
            subkey[2 * i + 1] =
              setBit(subkey[2 * i + 1], getBit(V, ((2*(j-8)) + 1 + 16)), (4 * j + 1));
            subkey[2 * i + 1] =
              setBit(subkey[2 * i + 1], getBit(V, ((2*(j-8)) + 16)), (4 * j));
            
        }
        
        /*
        for (j = 0; j < 6; j++) {
            subkey[2 * i] = setBit(
              subkey[2 * i], getBit(Constants[i], j), ConstantsLocation[j]);
            // The addition of the round constants of the round key
        }

        // always having 1 on the blockSize-1 round key
        subkey[2 * i + 1] = setBit(subkey[2 * i + 1], 0x01, 63);
        */

        uint16_t keyStateUpdated[8];
        keyStateUpdated[7] = rotateRight16Bit(keyState[1], 2);
        keyStateUpdated[6] = rotateRight16Bit(keyState[0], 12);
        keyStateUpdated[5] = keyState[7];
        keyStateUpdated[4] = keyState[6];
        keyStateUpdated[3] = keyState[5];
        keyStateUpdated[2] = keyState[4];
        keyStateUpdated[1] = keyState[3];
        keyStateUpdated[0] = keyState[2];

        for (j = 0; j < 8; j++) {
            keyState[j] = keyStateUpdated[j];
        }
    }

    // for ( i=0; i<Rounds; i++)
    //{
    //    printf("Round %u round key %016"PRIx64" %016"PRIx64 "\n\n",i,
    //    subkey[(2*(i))+1], subkey[(2*(i))]);
    //}

    return subkey;
}

//----------------------------------
// Encryption
//----------------------------------
// Start encryption

uint64_t
encrypt(uint64_t in, uint64_t* subkey, uint16_t Rounds, _Bool Roundwise)
{

#define out in
    uint16_t RoundNr;
    uint64_t text;


    for (RoundNr = 1; RoundNr < Rounds; RoundNr++) { // Start "for"
        uint16_t temp;
#define SboxNr temp
#define PBit temp


        //----------------------------------
        // Xor with roundkey
        //----------------------------------
        text = base3Add(in, subkey[RoundNr - 1]);


        //----------------------------------
        // S-Boxes
        //----------------------------------
        for (SboxNr = 0; SboxNr < 16; SboxNr++) {
            uint16_t SboxVal;

            SboxVal = text & 0x0F;      // get lowest nibble
            text &= 0xFFFFFFFFFFFFFFF0; // kill lowest nibble
            text |= Sbox[SboxVal];      // put new value to lowest nibble (sbox)
            text = rotate4l_64(text);   // next(rotate by one nibble)
        }


        //----------------------------------
        // P-Box
        //----------------------------------
        for (PBit = 0, out = 0; PBit < 32; PBit++) {
            // next(rotate by one bit) and put new value to lowest bit (pbox)
            out = rotate2l_64(out);
            out |= ((text >> ((31 - Pbox[PBit])*2) & 0x3));
        }


    } // End "for"

    text = base3Add(in, subkey[RoundNr - 1]);


    return text;
}



uint64_t*
encrypt128(uint64_t  inHigh,
           uint64_t  inLow,
           uint64_t* subkey,
           uint16_t  Rounds,
           _Bool     Roundwise)

{
    uint64_t* retVal = (uint64_t*)malloc(2 * sizeof(uint64_t));


// note outHigh is the same is inHigh the same goes with low.
#define outHigh inHigh
#define outLow inLow
    uint16_t RoundNr;
    uint64_t textHigh;
    uint64_t textLow;

    for (RoundNr = 1; RoundNr < Rounds; RoundNr++) {

        //uint16_t tempHigh;
        //uint16_t tempLow;
        uint16_t temp;

        // printf("Round %u round key %016"PRIx64" %016"PRIx64 "\n\n", RoundNr,
        // subkey[2*(RoundNr-1)+1], subkey[2*(RoundNr-1)]);

        textLow  = base3Add(inLow, subkey[2 * (RoundNr - 1)]);
        textHigh = base3Add(inHigh, subkey[2 * (RoundNr - 1) + 1]);

        // printf("Encryption round %i key low index:%i key high index
        // %i\n",RoundNr, (2*(RoundNr-1)),(2*(RoundNr-1)+1));

        for (SboxNr = 0; SboxNr < 16; SboxNr++) {
            uint16_t SboxValHigh;
            uint16_t SboxValLow;

            SboxValHigh = textHigh & 0x0F;
            SboxValLow  = textLow & 0x0F;
            // get lowest nibble
            textHigh &= 0xFFFFFFFFFFFFFFF0;
            textLow &= 0xFFFFFFFFFFFFFFF0; // kill lowest nibble

            textHigh |= Sbox[SboxValHigh];
            textLow |= Sbox[SboxValLow]; // put new value to lowest nibble
                                         // (sbox)

            textHigh = rotate4l_64(textHigh);
            textLow = rotate4l_64(textLow); // next(rotate by one nibble)
        }

        outHigh = 0;
        outLow  = 0;

        //uint8_t bitNum;

        // The four cases that they could permute differnetly form text to
        // output
        for (PBit = 0; PBit < 64; PBit++) {
            uint8_t bitNum = Pbox128[PBit];
            if (PBit < 32) {

                if (bitNum < 32) {
                    outLow = setDigitBase3(outLow, getDigitBase3(textLow, PBit), bitNum);
                } else {
                    outHigh =
                      setDigitBase3(outHigh, getDigitBase3(textLow, PBit), (bitNum - 32));
                }

            } else {
                if (bitNum < 32) {
                    outLow =
                      setDigitBase3(outLow, getDigitBase3(textHigh, (PBit - 32)), bitNum);
                } else {
                    outHigh =
                      setDigitBase3(outHigh, getDigitBase3(textHigh, (PBit - 32)), (bitNum - 32));
                }
            }
        }
    }
    // printf("Encryption final XOR round %i key low index:%i key high index
    // %i\n",RoundNr, (2*(RoundNr-1)),(2*(RoundNr-1)+1));

    retVal[0] = base3Add(inLow, subkey[2 * (RoundNr - 1)]);
    retVal[1] = base3Add(inHigh, subkey[2 * (RoundNr - 1) + 1]);


    return retVal;
}

// End encryption

//----------------------------------
// Decryption
//----------------------------------
// Start decryption

uint64_t
decrypt(uint64_t in, uint64_t* subkey, uint16_t Rounds, _Bool Roundwise)
{
#define out in
    uint16_t RoundNr;
    uint64_t text;

    for (RoundNr = 1; RoundNr <= Rounds; RoundNr++) { // Start "for"
        //uint64_t key_temp;
        uint16_t temp;
#define SboxNr temp
#define PBit temp

        //----------------------------------
        // Xor with roundkey
        //----------------------------------
        text = base3Add(in, base3Invert(subkey[Rounds - RoundNr]));


        //----------------------------------
        // P-Box
        //----------------------------------
        for (PBit = 0, out = 0; PBit < 32; PBit++) {
            // next(rotate by one bit) and put new value to lowest bit (pbox)
            out = rotate2l_64(out);
            out |= ((text >> ((31 - ((PboxInv[PBit]))) * 2) ) & 0x3);
        }


        //----------------------------------
        // S-Boxes
        //----------------------------------
        for (SboxNr = 0; SboxNr < 16; SboxNr++) {
            uint16_t SboxVal;

            SboxVal = out & 0x0F;
            out &= 0xFFFFFFFFFFFFFFF0;
            out |= SboxInv[SboxVal];
            out  = rotate4l_64(out);
        }


    } // End "for"

    return text;
}

uint64_t*
decrypt128(uint64_t  inHigh,
           uint64_t  inLow,
           uint64_t* subkey,
           uint16_t  Rounds,
           _Bool     Roundwise)

{
    uint64_t* retVal = (uint64_t*)malloc(2 * sizeof(uint64_t));

#define outHigh inHigh
#define outLow inLow
    uint16_t RoundNr;
    uint64_t textHigh;
    uint64_t textLow;
    uint16_t temp;

    // XOR operation

    for (RoundNr = 1; RoundNr <= Rounds; RoundNr++) {
        // printf("Decyrption key low:%i key high
        // %i\n",((2*Rounds)-(2*(RoundNr))),(2*Rounds)-(2*(RoundNr))+1);


        textHigh = base3Add(inHigh, base3Invert(subkey[(2 * Rounds) - (2 * (RoundNr)) + 1]));
        textLow  = base3Add(inLow, base3Invert(subkey[(2 * Rounds) - (2 * (RoundNr))]));


        // In the last round nly the textHigh and textLow are used that
        // is why retVal gets text rather tahn out.
        outHigh = 0;
        outLow  = 0;

        for (PBit = 0; PBit < 64; PBit++) {
            uint8_t bitNum = Pbox128Inv[PBit];
            if (PBit < 32) {

                if (bitNum < 32) {
                    outLow = setDigitBase3(outLow, getDigitBase3(textLow, PBit), bitNum);
                } else {
                    outHigh =
                      setDigitBase3(outHigh, getDigitBase3(textLow, PBit), (bitNum - 32));
                }

            } else {
                if (bitNum < 32) {
                    outLow =
                      setDigitBase3(outLow, getDigitBase3(textHigh, (PBit - 32)), bitNum);
                } else {
                    outHigh =
                      setDigitBase3(outHigh, getDigitBase3(textHigh, (PBit - 32)), (bitNum - 32));
                }
            }
        }

        for (SboxNr = 0; SboxNr < 16; SboxNr++) {
            uint16_t SboxValHigh;
            uint16_t SboxValLow;
            SboxValHigh = outHigh & 0x0F;
            SboxValLow  = outLow & 0x0F;
            // get lowest nibble
            outHigh &= 0xFFFFFFFFFFFFFFF0;
            outLow &= 0xFFFFFFFFFFFFFFF0; // kill lowest nibble

            outHigh |= SboxInv[SboxValHigh];
            outLow  |= SboxInv[SboxValLow];
                    // put new value to lowest nibble (sbox)

            outHigh = rotate4l_64(outHigh);
            outLow  = rotate4l_64(outLow); // next(rotate by one nibble)
        }
    }

    retVal[1] = textHigh;
    retVal[0] = textLow;

    return retVal;
}
// End decryption

uint64_t
base3Add(uint64_t in, uint64_t subkey)
{
    uint64_t retVal = 0;
    uint64_t temp1;
    uint64_t temp2;

    for(uint8_t i = 0; i < 32; i++)
    {
        temp1 = ((in >> (i * 2)) & 0x3); //Get two bit quantity and mask
        temp2 = ((subkey >> (i * 2)) & 0x3); //Get two bit quantity and mask

        temp1 = (temp1+temp2) % 3; //Mod by three to get a base 3 number

        retVal = retVal | (temp1 << (i*2)); //put base 3 number into the return value
    }

    return retVal;
}

uint64_t
base3Invert(uint64_t in)
{
    uint64_t retVal = 0;
    int64_t temp;

    for(uint8_t i = 0; i < 32; i++)
    {
        temp = (((((in >> (i * 2)) & 0x3) * (-1)) + 3) % 3); //gets value, masks and inverts the base 3 number
        retVal = retVal | (temp << (i*2)); //put base 3 number into the return value
    }

    return retVal;
}
