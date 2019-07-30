/*
GIFT-128 (bitslice) implementations
Prepared by: Siang Meng Sim
Email: crypto.s.m.sim@gmail.com
Date: 23 Mar 2019
*/
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "crypto.h"

/*Round constants*/
const unsigned char GIFT_RC[40] = {
    0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F,
    0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E, 0x1D, 0x3A, 0x35, 0x2B,
    0x16, 0x2C, 0x18, 0x30, 0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E,
    0x1C, 0x38, 0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A
};

uint32_t rowperm(uint32_t S, int B0_pos, int B1_pos, int B2_pos, int B3_pos){
    uint32_t T=0;
    int b;
    for(b=0; b<8; b++){
        T |= ((S>>(4*b+0))&0x1)<<(b + 8*B0_pos);
        T |= ((S>>(4*b+1))&0x1)<<(b + 8*B1_pos);
        T |= ((S>>(4*b+2))&0x1)<<(b + 8*B2_pos);
        T |= ((S>>(4*b+3))&0x1)<<(b + 8*B3_pos);
    }
    return T;
}

void giftb128(uint8_t P[16], const uint8_t K[16], uint8_t C[16]){
    int round;
    uint32_t S[4],T;
    uint16_t W[8],T6,T7;

    S[0] = ((uint32_t)P[ 0]<<24) | ((uint32_t)P[ 1]<<16) | ((uint32_t)P[ 2]<<8) | (uint32_t)P[ 3];
    S[1] = ((uint32_t)P[ 4]<<24) | ((uint32_t)P[ 5]<<16) | ((uint32_t)P[ 6]<<8) | (uint32_t)P[ 7];
    S[2] = ((uint32_t)P[ 8]<<24) | ((uint32_t)P[ 9]<<16) | ((uint32_t)P[10]<<8) | (uint32_t)P[11];
    S[3] = ((uint32_t)P[12]<<24) | ((uint32_t)P[13]<<16) | ((uint32_t)P[14]<<8) | (uint32_t)P[15];

    W[0] = ((uint16_t)K[ 0]<<8) | (uint16_t)K[ 1];
    W[1] = ((uint16_t)K[ 2]<<8) | (uint16_t)K[ 3];
    W[2] = ((uint16_t)K[ 4]<<8) | (uint16_t)K[ 5];
    W[3] = ((uint16_t)K[ 6]<<8) | (uint16_t)K[ 7];
    W[4] = ((uint16_t)K[ 8]<<8) | (uint16_t)K[ 9];
    W[5] = ((uint16_t)K[10]<<8) | (uint16_t)K[11];
    W[6] = ((uint16_t)K[12]<<8) | (uint16_t)K[13];
    W[7] = ((uint16_t)K[14]<<8) | (uint16_t)K[15];

    for(round=0; round<40; round++){
        /*===SubCells===*/
        S[1] ^= S[0] & S[2];
        S[0] ^= S[1] & S[3];
        S[2] ^= S[0] | S[1];
        S[3] ^= S[2];
        S[1] ^= S[3];
        S[3] ^= 0xffffffff;
        S[2] ^= S[0] & S[1];

        T = S[0];
        S[0] = S[3];
        S[3] = T;


        /*===PermBits===*/
        S[0] = rowperm(S[0],0,3,2,1);
        S[1] = rowperm(S[1],1,0,3,2);
        S[2] = rowperm(S[2],2,1,0,3);
        S[3] = rowperm(S[3],3,2,1,0);

        /*===AddRoundKey===*/
        S[2] ^= ((uint32_t)W[2]<<16) | (uint32_t)W[3];
        S[1] ^= ((uint32_t)W[6]<<16) | (uint32_t)W[7];

        /*Add round constant*/
        S[3] ^= 0x80000000 ^ GIFT_RC[round];

        /*===Key state update===*/
        T6 = (W[6]>>2) | (W[6]<<14);
        T7 = (W[7]>>12) | (W[7]<<4);
        W[7] = W[5];
        W[6] = W[4];
        W[5] = W[3];
        W[4] = W[2];
        W[3] = W[1];
        W[2] = W[0];
        W[1] = T7;
        W[0] = T6;
    }

    C[ 0] = S[0]>>24;
    C[ 1] = S[0]>>16;
    C[ 2] = S[0]>>8;
    C[ 3] = S[0];
    C[ 4] = S[1]>>24;
    C[ 5] = S[1]>>16;
    C[ 6] = S[1]>>8;
    C[ 7] = S[1];
    C[ 8] = S[2]>>24;
    C[ 9] = S[2]>>16;
    C[10] = S[2]>>8;
    C[11] = S[2];
    C[12] = S[3]>>24;
    C[13] = S[3]>>16;
    C[14] = S[3]>>8;
    C[15] = S[3];

return;}

void giftwrap(uint8_t P[16], const uint8_t K[16], uint8_t C[16]){
    uint64_t plain_l = 0, plain_h = 0;

    // unpack the input from the bitslice input format
    for (uint8_t i = 0; i < 4; i++) {
        for (uint8_t j = 0; j < 2; j++) {
            for (int8_t k = 7; k >= 0; k--) {
                //printf("adding bit %03d [%d] from plaintext byte %d [%02hhx]\n",
                //       (32 + i - 32 * j + 4 * k + 64), (P[4*i + j]>>k) & 0x1, 4*i + j, P[4*i + j]);
                plain_h |= (uint64_t)((P[4 * i + j]     >> k) & 0x1) << (32 + i - 32 * j + 4 * k);
                plain_l |= (uint64_t)((P[4 * i + j + 2] >> k) & 0x1) << (32 + i - 32 * j + 4 * k);
            }
        }
    }
    //Switch the bit order, because Will's stuff is silly.
    /*
    uint64_t temp1 = 0, temp2 = 0;
    for (uint8_t i = 0; i<64; i++) {
        temp1 |= ((plain_h >> i) & 0x1) << (63 - i);
        temp2 |= ((plain_l >> i) & 0x1) << (63 - i);
    }
    plain_h = temp2;
    plain_l = temp1;
    */

	uint8_t k[16];
	for (uint8_t i = 0; i < 16; i++) {
		k[i] = K[i];
	}
    for (uint8_t i = 0; i < 4; i++) {
        uint8_t tmp;
        uint8_t inv = 7 - i;
        tmp         = k[i];
        k[i]        = k[inv];
        k[inv]      = tmp;

        tmp        = k[i + 8];
        k[i + 8]   = k[inv + 8];
        k[inv + 8] = tmp;
    }

    /*
    for (uint8_t i = 0; i < 8; i++) {
        uint8_t tmp;
        uint8_t inv = 2*i + 1;
        tmp         = k[2*i];
        k[2*i]      = k[inv];
        k[inv]      = tmp;
    }*/
    uint64_t key_h = *((uint64_t *)k);
    uint64_t key_l = *((uint64_t *)(k + 8));


    uint64_t *keys = key_schedule128(key_h, key_l, 40, 0);
    uint64_t *cyph = encrypt128(plain_h, plain_l, keys, 40, 0);

    //repack the output
    for (uint8_t i = 0; i < 4; i++) {
        for (uint8_t j = 0; j < 2; j++) {
            for (int8_t k = 7; k >= 0; k--) {
                C[4 * i + j]     |= ((cyph[1] >> (32 + i - 32 * j + 4 * k)) & 0x1) << k;
                C[4 * i + j + 2] |= ((cyph[0] >> (32 + i - 32 * j + 4 * k)) & 0x1) << k;
            }
        }
    }
    free(keys);
    free(cyph);
    return;
}
