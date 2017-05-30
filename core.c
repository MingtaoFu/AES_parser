#include "main.h"

#include <stdio.h>

#define GETU32(p) (*((uint32_t*)(p)))
#define ROTATE(a,n)  ({ register unsigned int ret;   \
                asm (           \
                "roll %1,%0"        \
                : "=r"(ret)     \
                : "I"(n), "0"(a)    \
                : "cc");        \
               ret;             \
            })
void print_storage2(char* sto, uint32_t* pt) {
    for (int i = 0; i < 4; i++) {
        uint32_t t = pt[i];
        printf("%x\n", t );
        for (int j = 0; j < 4; j++) {
            sprintf(&sto[(i * 4 + j) * 3], "%02x ", (t >> (j * 8)) & 0xff );
            //printf("%02x ", (t >> (j * 2)) & 0xff );
        }
        printf("\n");

    }
}

int AES_set_decrypt_key2_test(const unsigned char *userKey, const int bits, AES_KEY *key) {
    printf("1111111111\n");

    uint32_t *rk;
    int i, j, status;
    uint32_t temp;

    printf("333333333333333\n");
    /* first, start with an encryption schedule */
    status = AES_set_encrypt_key2(userKey, NULL, key);
    //if (status < 0)
     //   return status;

    rk = key->rd_key;

    /* invert the order of the round keys: */
    for (i = 0, j = 4*(key->rounds); i < j; i += 4, j -= 4) {
        temp = rk[i    ]; rk[i    ] = rk[j    ]; rk[j    ] = temp;
        temp = rk[i + 1]; rk[i + 1] = rk[j + 1]; rk[j + 1] = temp;
        temp = rk[i + 2]; rk[i + 2] = rk[j + 2]; rk[j + 2] = temp;
        temp = rk[i + 3]; rk[i + 3] = rk[j + 3]; rk[j + 3] = temp;
    }
    printf("333333333333333\n");
    /* apply the inverse MixColumn transform to all round keys but the first and the last: */
    for (i = 1; i < (key->rounds); i++) {
        rk += 4;
        for (j = 0; j < 4; j++) {
            uint32_t tp1, tp2, tp4, tp8, tp9, tpb, tpd, tpe, m;

            tp1 = rk[j];
            m = tp1 & 0x80808080;
            tp2 = ((tp1 & 0x7f7f7f7f) << 1) ^
                  ((m - (m >> 7)) & 0x1b1b1b1b);
            m = tp2 & 0x80808080;
            tp4 = ((tp2 & 0x7f7f7f7f) << 1) ^
                  ((m - (m >> 7)) & 0x1b1b1b1b);
            m = tp4 & 0x80808080;
            tp8 = ((tp4 & 0x7f7f7f7f) << 1) ^
                  ((m - (m >> 7)) & 0x1b1b1b1b);
            tp9 = tp8 ^ tp1;
            tpb = tp9 ^ tp2;
            tpd = tp9 ^ tp4;
            tpe = tp8 ^ tp4 ^ tp2;
            rk[j] = tpe ^ ROTATE(tpd, 16) ^
                    ROTATE(tp9, 8) ^ ROTATE(tpb, 24);

        }
    }
    printf("333333333333333\n");

    return 0;
}

void AES_decrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key) {

    const uint32_t *rk;
    uint32_t s0, s1, s2, s3, t[4];
    int r;

    rk = key->rd_key;

    /*
     * map byte array block to cipher state
     * and add initial round key:
     */

    s0 = GETU32(in     );
    s1 = GETU32(in +  4);
    s2 = GETU32(in +  8);
    s3 = GETU32(in + 12);

    //prefetch256(Td4);

    t[0] = (uint32_t)Td4[(s0      ) & 0xff]       ^
           (uint32_t)Td4[(s3 >>  8) & 0xff] <<  8 ^
           (uint32_t)Td4[(s2 >> 16) & 0xff] << 16 ^
           (uint32_t)Td4[(s1 >> 24)       ] << 24;
    t[1] = (uint32_t)Td4[(s1      ) & 0xff]       ^
           (uint32_t)Td4[(s0 >>  8) & 0xff] <<  8 ^
           (uint32_t)Td4[(s3 >> 16) & 0xff] << 16 ^
           (uint32_t)Td4[(s2 >> 24)       ] << 24;
    t[2] = (uint32_t)Td4[(s2      ) & 0xff]       ^
           (uint32_t)Td4[(s1 >>  8) & 0xff] <<  8 ^
           (uint32_t)Td4[(s0 >> 16) & 0xff] << 16 ^
           (uint32_t)Td4[(s3 >> 24)       ] << 24;
    t[3] = (uint32_t)Td4[(s3      ) & 0xff]       ^
           (uint32_t)Td4[(s2 >>  8) & 0xff] <<  8 ^
           (uint32_t)Td4[(s1 >> 16) & 0xff] << 16 ^
           (uint32_t)Td4[(s0 >> 24)       ] << 24;

    /* now do the linear transform using words */
    {
        int i;
        uint32_t tp1, tp2, tp4, tp8, tp9, tpb, tpd, tpe, m;

        for (i = 0; i < 4; i++) {
            tp1 = t[i];
            m = tp1 & 0x80808080;
            tp2 = ((tp1 & 0x7f7f7f7f) << 1) ^
                ((m - (m >> 7)) & 0x1b1b1b1b);
            m = tp2 & 0x80808080;
            tp4 = ((tp2 & 0x7f7f7f7f) << 1) ^
                ((m - (m >> 7)) & 0x1b1b1b1b);
            m = tp4 & 0x80808080;
            tp8 = ((tp4 & 0x7f7f7f7f) << 1) ^
                ((m - (m >> 7)) & 0x1b1b1b1b);
            tp9 = tp8 ^ tp1;
            tpb = tp9 ^ tp2;
            tpd = tp9 ^ tp4;
            tpe = tp8 ^ tp4 ^ tp2;
            t[i] = tpe ^ ROTATE(tpd,16) ^
                ROTATE(tp9,8) ^ ROTATE(tpb,24);
            t[i] ^= rk[4+i];
        }
    }

    s0 = t[0]; s1 = t[1]; s2 = t[2]; s3 = t[3];

    /*
     * Nr - 2 full rounds:
     */
    for (rk+=8,r=key->rounds-2; r>0; rk+=4,r--) {
        t[0] = (uint32_t)Td4[(s0      ) & 0xff]       ^
               (uint32_t)Td4[(s3 >>  8) & 0xff] <<  8 ^
               (uint32_t)Td4[(s2 >> 16) & 0xff] << 16 ^
               (uint32_t)Td4[(s1 >> 24)       ] << 24;
        t[1] = (uint32_t)Td4[(s1      ) & 0xff]       ^
               (uint32_t)Td4[(s0 >>  8) & 0xff] <<  8 ^
               (uint32_t)Td4[(s3 >> 16) & 0xff] << 16 ^
               (uint32_t)Td4[(s2 >> 24)       ] << 24;
        t[2] = (uint32_t)Td4[(s2      ) & 0xff]       ^
               (uint32_t)Td4[(s1 >>  8) & 0xff] <<  8 ^
               (uint32_t)Td4[(s0 >> 16) & 0xff] << 16 ^
               (uint32_t)Td4[(s3 >> 24)       ] << 24;
        t[3] = (uint32_t)Td4[(s3      ) & 0xff]       ^
               (uint32_t)Td4[(s2 >>  8) & 0xff] <<  8 ^
               (uint32_t)Td4[(s1 >> 16) & 0xff] << 16 ^
               (uint32_t)Td4[(s0 >> 24)       ] << 24;

    /* now do the linear transform using words */
    {
        int i;
        uint32_t tp1, tp2, tp4, tp8, tp9, tpb, tpd, tpe, m;

        for (i = 0; i < 4; i++) {
            tp1 = t[i];
            m = tp1 & 0x80808080;
            tp2 = ((tp1 & 0x7f7f7f7f) << 1) ^
                ((m - (m >> 7)) & 0x1b1b1b1b);
            m = tp2 & 0x80808080;
            tp4 = ((tp2 & 0x7f7f7f7f) << 1) ^
                ((m - (m >> 7)) & 0x1b1b1b1b);
            m = tp4 & 0x80808080;
            tp8 = ((tp4 & 0x7f7f7f7f) << 1) ^
                ((m - (m >> 7)) & 0x1b1b1b1b);
            tp9 = tp8 ^ tp1;
            tpb = tp9 ^ tp2;
            tpd = tp9 ^ tp4;
            tpe = tp8 ^ tp4 ^ tp2;
            t[i] = tpe ^ ROTATE(tpd,16) ^
                ROTATE(tp9,8) ^ ROTATE(tpb,24);
            t[i] ^= rk[i];
        }
    }

        s0 = t[0]; s1 = t[1]; s2 = t[2]; s3 = t[3];
    }
    /*
     * apply last round and
     * map cipher state to byte array block:
     */
    //prefetch256(Td4);

    *(uint32_t*)(out+0) =
            ((uint32_t)Td4[(s0      ) & 0xff])    ^
            ((uint32_t)Td4[(s3 >>  8) & 0xff] <<  8) ^
            ((uint32_t)Td4[(s2 >> 16) & 0xff] << 16) ^
            ((uint32_t)Td4[(s1 >> 24)       ] << 24) ^
            rk[0];
    *(uint32_t*)(out+4) =
            ((uint32_t)Td4[(s1      ) & 0xff])     ^
            ((uint32_t)Td4[(s0 >>  8) & 0xff] <<  8) ^
            ((uint32_t)Td4[(s3 >> 16) & 0xff] << 16) ^
            ((uint32_t)Td4[(s2 >> 24)       ] << 24) ^
            rk[1];
    *(uint32_t*)(out+8) =
            ((uint32_t)Td4[(s2      ) & 0xff])     ^
            ((uint32_t)Td4[(s1 >>  8) & 0xff] <<  8) ^
            ((uint32_t)Td4[(s0 >> 16) & 0xff] << 16) ^
            ((uint32_t)Td4[(s3 >> 24)       ] << 24) ^
            rk[2];
    *(uint32_t*)(out+12) =
            ((uint32_t)Td4[(s3      ) & 0xff])     ^
            ((uint32_t)Td4[(s2 >>  8) & 0xff] <<  8) ^
            ((uint32_t)Td4[(s1 >> 16) & 0xff] << 16) ^
            ((uint32_t)Td4[(s0 >> 24)       ] << 24) ^
            rk[3];
}

int AES_set_encrypt_key2(const unsigned char *userKey, const int bits, AES_KEY *key) {
    printf("-------------------\n%d\n--------------------", 1);
    uint32_t *rk, temp;
    int i = 0;

    rk = key->rd_key;
    key->rounds = 10;

    rk[0] = GETU32(userKey     );
    rk[1] = GETU32(userKey +  4);
    rk[2] = GETU32(userKey +  8);
    rk[3] = GETU32(userKey + 12);

    while(1) {
        temp = rk[3];
        /*
        printf("\n********\n%8x\n*******\n",
               ((uint32_t)((temp >>  8) & 0xff)      ) ^
               ((uint32_t)((temp >> 16) & 0xff) <<  8) ^
               ((uint32_t)((temp >> 24)       ) << 16) ^
               ((uint32_t)((temp      ) & 0xff) << 24)
        );
        printf("%8x", rcon[i]);
         */
        rk[4] = rk[0] ^
                ((uint32_t)Te4[(temp >>  8) & 0xff]      ) ^
                ((uint32_t)Te4[(temp >> 16) & 0xff] <<  8) ^
                ((uint32_t)Te4[(temp >> 24)       ] << 16) ^
                ((uint32_t)Te4[(temp      ) & 0xff] << 24) ^
                rcon[i];
        rk[5] = rk[1] ^ rk[4];
        rk[6] = rk[2] ^ rk[5];
        rk[7] = rk[3] ^ rk[6];
        if (++i == 10) {
            break;
        }
        rk += 4;
    }

    rk = key->rd_key;
    /*
    for (int j = 0; j < 40; j++) {
        if (j % 4 == 0) {
            printf("\n");
        }
        printf("%8x ", rk[j]);
    }
     */
}

void AES_encrypt_data2(const unsigned char *in, unsigned char *out, const AES_KEY *key) {
    const uint32_t *rk;
    uint32_t s[4], t[4];

    rk = key->rd_key;

    t[0] = GETU32(in     );
    t[1] = GETU32(in +  4);
    t[2] = GETU32(in +  8);
    t[3] = GETU32(in + 12);
    // input
    print_storage2(sto.states[0], t);

    s[0] = t[0] ^ rk[0];
    s[1] = t[1] ^ rk[1];
    s[2] = t[2] ^ rk[2];
    s[3] = t[3] ^ rk[3];
    // addRoundKey
    print_storage2(sto.states[1], s);

    for (int round = 0; round < 9; round++) {
        t[0] = (uint32_t) Te4[(s[0]) & 0xff] ^
               (uint32_t) Te4[(s[0] >> 8) & 0xff] << 8 ^
               (uint32_t) Te4[(s[0] >> 16) & 0xff] << 16 ^
               (uint32_t) Te4[(s[0] >> 24)] << 24;
        t[1] = (uint32_t) Te4[(s[1]) & 0xff] ^
               (uint32_t) Te4[(s[1] >> 8) & 0xff] << 8 ^
               (uint32_t) Te4[(s[1] >> 16) & 0xff] << 16 ^
               (uint32_t) Te4[(s[1] >> 24)] << 24;
        t[2] = (uint32_t) Te4[(s[2]) & 0xff] ^
               (uint32_t) Te4[(s[2] >> 8) & 0xff] << 8 ^
               (uint32_t) Te4[(s[2] >> 16) & 0xff] << 16 ^
               (uint32_t) Te4[(s[2] >> 24)] << 24;
        t[3] = (uint32_t) Te4[(s[3]) & 0xff] ^
               (uint32_t) Te4[(s[3] >> 8) & 0xff] << 8 ^
               (uint32_t) Te4[(s[3] >> 16) & 0xff] << 16 ^
               (uint32_t) Te4[(s[3] >> 24)] << 24;
        //subBytes
        print_storage2(sto.states[round * 4 + 2], t);

        s[0] = ((t[0]) & 0xff) ^
               ((t[1] >> 8) & 0xff) << 8 ^
               ((t[2] >> 16) & 0xff) << 16 ^
               ((t[3] >> 24)) << 24;
        s[1] = ((t[1]) & 0xff) ^
               ((t[2] >> 8) & 0xff) << 8 ^
               ((t[3] >> 16) & 0xff) << 16 ^
               ((t[0] >> 24)) << 24;
        s[2] = ((t[2]) & 0xff) ^
               ((t[3] >> 8) & 0xff) << 8 ^
               ((t[0] >> 16) & 0xff) << 16 ^
               ((t[1] >> 24)) << 24;
        s[3] = ((t[3]) & 0xff) ^
               ((t[0] >> 8) & 0xff) << 8 ^
               ((t[1] >> 16) & 0xff) << 16 ^
               ((t[2] >> 24)) << 24;
        // shiftRows
        print_storage2(sto.states[round * 4 + 3], s);

        {
            int i;
            uint32_t r0, r1, r2;

            for (i = 0; i < 4; i++) {
                r0 = s[i];
                r1 = r0 & 0x80808080;
                // 低7位左移, 进行模除
                r2 = ((r0 & 0x7f7f7f7f) << 1) ^
                     ((r1 - (r1 >> 7)) & 0x1b1b1b1b);
                s[i] = r2 ^ ROTATE(r2, 24) ^ ROTATE(r0, 24) ^
                       ROTATE(r0, 16) ^ ROTATE(r0, 8);
                //t[i] ^= rk[4+i];
            }
        }
        // mixColumn
        print_storage2(sto.states[round * 4 + 4], s);

        for (int i = 0; i < 4; i++) {
            s[i] ^= rk[(round + 1) * 4 + i];
        }
        // addRoundKey
        print_storage2(sto.states[round * 4 + 5], s);
    }

    t[0] = (uint32_t) Te4[(s[0]) & 0xff] ^
           (uint32_t) Te4[(s[0] >> 8) & 0xff] << 8 ^
           (uint32_t) Te4[(s[0] >> 16) & 0xff] << 16 ^
           (uint32_t) Te4[(s[0] >> 24)] << 24;
    t[1] = (uint32_t) Te4[(s[1]) & 0xff] ^
           (uint32_t) Te4[(s[1] >> 8) & 0xff] << 8 ^
           (uint32_t) Te4[(s[1] >> 16) & 0xff] << 16 ^
           (uint32_t) Te4[(s[1] >> 24)] << 24;
    t[2] = (uint32_t) Te4[(s[2]) & 0xff] ^
           (uint32_t) Te4[(s[2] >> 8) & 0xff] << 8 ^
           (uint32_t) Te4[(s[2] >> 16) & 0xff] << 16 ^
           (uint32_t) Te4[(s[2] >> 24)] << 24;
    t[3] = (uint32_t) Te4[(s[3]) & 0xff] ^
           (uint32_t) Te4[(s[3] >> 8) & 0xff] << 8 ^
           (uint32_t) Te4[(s[3] >> 16) & 0xff] << 16 ^
           (uint32_t) Te4[(s[3] >> 24)] << 24;
    //subBytes
    print_storage2(sto.states[38], t);

    s[0] = ((t[0]) & 0xff) ^
           ((t[1] >> 8) & 0xff) << 8 ^
           ((t[2] >> 16) & 0xff) << 16 ^
           ((t[3] >> 24)) << 24;
    s[1] = ((t[1]) & 0xff) ^
           ((t[2] >> 8) & 0xff) << 8 ^
           ((t[3] >> 16) & 0xff) << 16 ^
           ((t[0] >> 24)) << 24;
    s[2] = ((t[2]) & 0xff) ^
           ((t[3] >> 8) & 0xff) << 8 ^
           ((t[0] >> 16) & 0xff) << 16 ^
           ((t[1] >> 24)) << 24;
    s[3] = ((t[3]) & 0xff) ^
           ((t[0] >> 8) & 0xff) << 8 ^
           ((t[1] >> 16) & 0xff) << 16 ^
           ((t[2] >> 24)) << 24;
    // shiftRows
    print_storage2(sto.states[39], s);

    for (int i = 0; i < 4; i++) {
        s[i] ^= rk[40 + i];
    }
    // addRoundKey
    print_storage2(sto.states[40], s);
    // output
    print_storage2(sto.states[41], s);
}

void AES_decrypt_data2(const unsigned char *in, unsigned char *out, const AES_KEY *key) {

    const uint32_t *rk;
    uint32_t s[4], t[4];
    int r;

    rk = key->rd_key;

    printf("sadsadsadsadsa\n");
    /*
     * map byte array block to cipher state
     * and add initial round key:
     */

    t[0] = GETU32(in     );
    t[1] = GETU32(in +  4);
    t[2] = GETU32(in +  8);
    t[3] = GETU32(in + 12);
    // input
    print_storage2(sto.states[0], t);

    s[0] = t[0] ^ rk[0];
    s[1] = t[1] ^ rk[1];
    s[2] = t[2] ^ rk[2];
    s[3] = t[3] ^ rk[3];
    // addRoundKey
    print_storage2(sto.states[1], s);


    for (int round = 0; round < 9; round++) {
        t[0] = ((s[0]) & 0xff) ^
               ((s[1] >> 24)) << 24 ^
               ((s[2] >> 16) & 0xff) << 16 ^
               ((s[3] >>  8) & 0xff) <<  8;
        t[1] = ((s[1]) & 0xff) ^
               ((s[0] >> 8) & 0xff) << 8 ^
               ((s[3] >> 16) & 0xff) << 16 ^
               ((s[2] >> 24)) << 24;
        t[2] = ((s[2]) & 0xff) ^
               ((s[1] >> 8) & 0xff) << 8 ^
               ((s[0] >> 16) & 0xff) << 16 ^
               ((s[3] >> 24)) << 24;
        t[3] = ((s[3]) & 0xff) ^
               ((s[2] >> 8) & 0xff) << 8 ^
               ((s[1] >> 16) & 0xff) << 16 ^
               ((s[0] >> 24)) << 24;
        // invShiftRows
        print_storage2(sto.states[round * 4 + 2], t);


        s[0] = (uint32_t) Td4[(t[0]) & 0xff] ^
               (uint32_t) Td4[(t[0] >> 8) & 0xff] << 8 ^
               (uint32_t) Td4[(t[0] >> 16) & 0xff] << 16 ^
               (uint32_t) Td4[(t[0] >> 24)] << 24;
        s[1] = (uint32_t) Td4[(t[1]) & 0xff] ^
               (uint32_t) Td4[(t[1] >> 8) & 0xff] << 8 ^
               (uint32_t) Td4[(t[1] >> 16) & 0xff] << 16 ^
               (uint32_t) Td4[(t[1] >> 24)] << 24;
        s[2] = (uint32_t) Td4[(t[2]) & 0xff] ^
               (uint32_t) Td4[(t[2] >> 8) & 0xff] << 8 ^
               (uint32_t) Td4[(t[2] >> 16) & 0xff] << 16 ^
               (uint32_t) Td4[(t[2] >> 24)] << 24;
        s[3] = (uint32_t) Td4[(t[3]) & 0xff] ^
               (uint32_t) Td4[(t[3] >> 8) & 0xff] << 8 ^
               (uint32_t) Td4[(t[3] >> 16) & 0xff] << 16 ^
               (uint32_t) Td4[(t[3] >> 24)] << 24;
        //invSubBytes
        print_storage2(sto.states[round * 4 + 3], s);



        /* now do the linear transform using words */
        {
            int i;
            uint32_t tp1, tp2, tp4, tp8, tp9, tpb, tpd, tpe, m;

            for (i = 0; i < 4; i++) {
                tp1 = s[i];
                m = tp1 & 0x80808080;
                tp2 = ((tp1 & 0x7f7f7f7f) << 1) ^
                      ((m - (m >> 7)) & 0x1b1b1b1b);
                m = tp2 & 0x80808080;
                tp4 = ((tp2 & 0x7f7f7f7f) << 1) ^
                      ((m - (m >> 7)) & 0x1b1b1b1b);
                m = tp4 & 0x80808080;
                tp8 = ((tp4 & 0x7f7f7f7f) << 1) ^
                      ((m - (m >> 7)) & 0x1b1b1b1b);
                tp9 = tp8 ^ tp1;
                tpb = tp9 ^ tp2;
                tpd = tp9 ^ tp4;
                tpe = tp8 ^ tp4 ^ tp2;
                s[i] = tpe ^ ROTATE(tpd, 16) ^
                       ROTATE(tp9, 8) ^ ROTATE(tpb, 24);
                //t[i] ^= rk[4+i];
            }
        }
        // mixColumn
        print_storage2(sto.states[round * 4 + 4], s);

        for (int i = 0; i < 4; i++) {
            s[i] ^= rk[(round + 1) * 4 + i];
        }
        // addRoundKey
        print_storage2(sto.states[round * 4 + 5], s);
    }

    /*
     * apply last round and
     * map cipher state to byte array block:
     */

    //prefetch256(Td4);
    t[0] = ((s[0]) & 0xff) ^
           ((s[1] >> 24)) << 24 ^
           ((s[2] >> 16) & 0xff) << 16 ^
           ((s[3] >>  8) & 0xff) <<  8;
    t[1] = ((s[1]) & 0xff) ^
           ((s[0] >> 8) & 0xff) << 8 ^
           ((s[3] >> 16) & 0xff) << 16 ^
           ((s[2] >> 24)) << 24;
    t[2] = ((s[2]) & 0xff) ^
           ((s[1] >> 8) & 0xff) << 8 ^
           ((s[0] >> 16) & 0xff) << 16 ^
           ((s[3] >> 24)) << 24;
    t[3] = ((s[3]) & 0xff) ^
           ((s[2] >> 8) & 0xff) << 8 ^
           ((s[1] >> 16) & 0xff) << 16 ^
           ((s[0] >> 24)) << 24;
    // shiftRows
    print_storage2(sto.states[38], t);

    s[0] = (uint32_t) Td4[(t[0]) & 0xff] ^
           (uint32_t) Td4[(t[0] >> 8) & 0xff] << 8 ^
           (uint32_t) Td4[(t[0] >> 16) & 0xff] << 16 ^
           (uint32_t) Td4[(t[0] >> 24)] << 24;
    s[1] = (uint32_t) Td4[(t[1]) & 0xff] ^
           (uint32_t) Td4[(t[1] >> 8) & 0xff] << 8 ^
           (uint32_t) Td4[(t[1] >> 16) & 0xff] << 16 ^
           (uint32_t) Td4[(t[1] >> 24)] << 24;
    s[2] = (uint32_t) Td4[(t[2]) & 0xff] ^
           (uint32_t) Td4[(t[2] >> 8) & 0xff] << 8 ^
           (uint32_t) Td4[(t[2] >> 16) & 0xff] << 16 ^
           (uint32_t) Td4[(t[2] >> 24)] << 24;
    s[3] = (uint32_t) Td4[(t[3]) & 0xff] ^
           (uint32_t) Td4[(t[3] >> 8) & 0xff] << 8 ^
           (uint32_t) Td4[(t[3] >> 16) & 0xff] << 16 ^
           (uint32_t) Td4[(t[3] >> 24)] << 24;
    //subBytes
    print_storage2(sto.states[39], s);

    for (int i = 0; i < 4; i++) {
        s[i] ^= rk[40 + i];
    }
    // addRoundKey
    print_storage2(sto.states[40], s);
       // output
    print_storage2(sto.states[41], s);


}

void AES_encrypt2(const unsigned char *in, unsigned char *out, const AES_KEY *key) {
    const uint32_t *rk;
    uint32_t s0, s1, s2, s3, t[4];
    int r;

    rk = key->rd_key;

    s0 = 0x206F7754 ^ rk[0];
    s1 = 0x20656E4F ^ rk[1];
    s2 = 0x656E694E ^ rk[2];
    s3 = 0x6F775420 ^ rk[3];

    //prefetch256(Te4);

    t[0] = (uint32_t)Te4[(s0      ) & 0xff]       ^
           (uint32_t)Te4[(s1 >>  8) & 0xff] <<  8 ^
           (uint32_t)Te4[(s2 >> 16) & 0xff] << 16 ^
           (uint32_t)Te4[(s3 >> 24)       ] << 24;
    t[1] = (uint32_t)Te4[(s1      ) & 0xff]       ^
           (uint32_t)Te4[(s2 >>  8) & 0xff] <<  8 ^
           (uint32_t)Te4[(s3 >> 16) & 0xff] << 16 ^
           (uint32_t)Te4[(s0 >> 24)       ] << 24;
    t[2] = (uint32_t)Te4[(s2      ) & 0xff]       ^
           (uint32_t)Te4[(s3 >>  8) & 0xff] <<  8 ^
           (uint32_t)Te4[(s0 >> 16) & 0xff] << 16 ^
           (uint32_t)Te4[(s1 >> 24)       ] << 24;
    t[3] = (uint32_t)Te4[(s3      ) & 0xff]       ^
           (uint32_t)Te4[(s0 >>  8) & 0xff] <<  8 ^
           (uint32_t)Te4[(s1 >> 16) & 0xff] << 16 ^
           (uint32_t)Te4[(s2 >> 24)       ] << 24;

    /* now do the linear transform using words */
    {
        int i;
        uint32_t r0, r1, r2;

        for (i = 0; i < 4; i++) {
            r0 = t[i];
            r1 = r0 & 0x80808080;
            // 低7位左移, 进行模除
            r2 = ((r0 & 0x7f7f7f7f) << 1) ^
                 ((r1 - (r1 >> 7)) & 0x1b1b1b1b);
            t[i] = r2 ^ ROTATE(r2,24) ^ ROTATE(r0,24) ^
                   ROTATE(r0,16) ^ ROTATE(r0,8);
            t[i] ^= rk[4+i];
        }
    }
    s0 = t[0]; s1 = t[1]; s2 = t[2]; s3 = t[3];

    // * Nr - 2 full rounds:
    for (rk+=8,r=key->rounds-2; r>0; rk+=4,r--) {
        t[0] = (uint32_t)Te4[(s0      ) & 0xff]       ^
               (uint32_t)Te4[(s1 >>  8) & 0xff] <<  8 ^
               (uint32_t)Te4[(s2 >> 16) & 0xff] << 16 ^
               (uint32_t)Te4[(s3 >> 24)       ] << 24;
        t[1] = (uint32_t)Te4[(s1      ) & 0xff]       ^
               (uint32_t)Te4[(s2 >>  8) & 0xff] <<  8 ^
               (uint32_t)Te4[(s3 >> 16) & 0xff] << 16 ^
               (uint32_t)Te4[(s0 >> 24)       ] << 24;
        t[2] = (uint32_t)Te4[(s2      ) & 0xff]       ^
               (uint32_t)Te4[(s3 >>  8) & 0xff] <<  8 ^
               (uint32_t)Te4[(s0 >> 16) & 0xff] << 16 ^
               (uint32_t)Te4[(s1 >> 24)       ] << 24;
        t[3] = (uint32_t)Te4[(s3      ) & 0xff]       ^
               (uint32_t)Te4[(s0 >>  8) & 0xff] <<  8 ^
               (uint32_t)Te4[(s1 >> 16) & 0xff] << 16 ^
               (uint32_t)Te4[(s2 >> 24)       ] << 24;

        printf("打印第k%d轮2后的结果\n", r);
        printf("%8x\n", t[0]);
        printf("%8x\n", t[1]);
        printf("%8x\n", t[2]);
        printf("%8x\n", t[3]);
        /* now do the linear transform using words */
        printf("打印第k%d轮3后的结果\n", r);
        {
            int i;
            uint32_t r0, r1, r2;

            for (i = 0; i < 4; i++) {
                r0 = t[i];
                r1 = r0 & 0x80808080;
                // r2为 原值向左移一位，低位为0，然后模除
                r2 = ((r0 & 0x7f7f7f7f) << 1) ^
                     ((r1 - (r1 >> 7)) & 0x1b1b1b1b);

                printf("r1       ): %8x\n", r1);
                printf("r1-(r1>>7)&0x1b1b1b1b: %8x\n", (r1-(r1>>7))&0x1b1b1b1b);
                printf("r0: %8x\n", r0);
                printf("r1: %8x\n", r1);
                printf("r2    : %8x\n", r2);
                printf("r2->24: %8x\n", ROTATE(r2, 24));
                printf("r0->24: %8x\n", ROTATE(r0, 24));
                printf("r0->16: %8x\n", ROTATE(r0, 16));
                printf("r0-> 8: %8x\n", ROTATE(r0, 8));

                t[i] = r2 ^ ROTATE(r2,24) ^ ROTATE(r0,24) ^
                       ROTATE(r0,16) ^ ROTATE(r0,8);

                printf("%8x\n", t[i]);
                t[i] ^= rk[i];
            }
        }
        s0 = t[0]; s1 = t[1]; s2 = t[2]; s3 = t[3];

        printf("打印第k%d轮4后的结果\n", r);
        printf("%8x\n", s0);
        printf("%8x\n", s1);
        printf("%8x\n", s2);
        printf("%8x\n", s3);
    }
    /*
     * apply last round and
     * map cipher state to byte array block:
     */
    //prefetch256(Te4);

    *(uint32_t*)(out+0) =
            (uint32_t)Te4[(s0      ) & 0xff]       ^
            (uint32_t)Te4[(s1 >>  8) & 0xff] <<  8 ^
            (uint32_t)Te4[(s2 >> 16) & 0xff] << 16 ^
            (uint32_t)Te4[(s3 >> 24)       ] << 24 ^
            rk[0];
    *(uint32_t*)(out+4) =
            (uint32_t)Te4[(s1      ) & 0xff]       ^
            (uint32_t)Te4[(s2 >>  8) & 0xff] <<  8 ^
            (uint32_t)Te4[(s3 >> 16) & 0xff] << 16 ^
            (uint32_t)Te4[(s0 >> 24)       ] << 24 ^
            rk[1];
    *(uint32_t*)(out+8) =
            (uint32_t)Te4[(s2      ) & 0xff]       ^
            (uint32_t)Te4[(s3 >>  8) & 0xff] <<  8 ^
            (uint32_t)Te4[(s0 >> 16) & 0xff] << 16 ^
            (uint32_t)Te4[(s1 >> 24)       ] << 24 ^
            rk[2];
    *(uint32_t*)(out+12) =
            (uint32_t)Te4[(s3      ) & 0xff]       ^
            (uint32_t)Te4[(s0 >>  8) & 0xff] <<  8 ^
            (uint32_t)Te4[(s1 >> 16) & 0xff] << 16 ^
            (uint32_t)Te4[(s2 >> 24)       ] << 24 ^
            rk[3];
}
