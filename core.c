#include "main.h"

#include <stdio.h>

#define ROTATE(a,n)  ({ register unsigned int ret;   \
                asm (           \
                "roll %1,%0"        \
                : "=r"(ret)     \
                : "I"(n), "0"(a)    \
                : "cc");        \
               ret;             \
            })


int AES_set_decrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key) {

    uint32_t *rk;
    int i, j, status;
    uint32_t temp;

    /* first, start with an encryption schedule */
    status = AES_set_encrypt_key(userKey, bits, key);
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

    return 0;
}


void AES_decrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key)
{

    const uint32_t *rk;
    uint32_t s0, s1, s2, s3, t[4];
    int r;

    rk = key->rd_key;

    /*
     * map byte array block to cipher state
     * and add initial round key:
     */

    s0 = 0x5f50c329 ^ rk[0];
    s1 = 0xf6201457 ^ rk[1];
    s2 = 0xb3992240 ^ rk[2];
    s3 = 0x3ad7021a ^ rk[3];

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


int AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key) {
    uint32_t *rk, temp;
    int i = 0;

    rk = key->rd_key;
    key->rounds = 10;

    rk[0] = 0x74616854;
    rk[1] = 0x796D2073;
    rk[2] = 0x6E754B20;
    rk[3] = 0x75462067;

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
static void prefetch256(const void *table) {
    volatile unsigned long *t = (void*)table, ret;
    unsigned long sum;
    int i;
    for (sum = 0, i = 0; i < 256 / sizeof(t[0]); i += 32 / sizeof(t[0])) {
        sum ^= t[i];
    }
    ret = sum;
}


void AES_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key) {
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
    {   int i;
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
