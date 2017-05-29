#include <stdio.h>
#include "main.h"

int main() {
    AES_KEY aes_key;
    AES_set_encrypt_key(NULL, NULL, &aes_key);

    /*
    int rounds = aes_key.rounds + 1;
    for (int i = 0; i < rounds; i++) {
        for (int j = 0; j < 4; j++) {
            printf("%08x\n", aes_key.rd_key[i*4+j]);
            uint32_t word = aes_key.rd_key[i*4+j];
            for (int k = 0; k < 4; k++) {
                printf("%x ", (word >> (6 - 2 * k)) & 0xff);
            }
            printf("\n");
        }
    }
     */
    const unsigned char paint[] =
            {0x54, 0x77, 0x6F, 0x20, 0x4F, 0x6E, 0x65,
             0x20, 0x4E, 0x69, 0x6E, 0x65, 0x20, 0x54, 0x77, 0x6F};
    unsigned char out[16];
    AES_encrypt(paint, out, &aes_key);
    for (int i = 0; i < 16; i++) {
        printf("%x", out[i]);
    }

    AES_set_decrypt_key(NULL, NULL, &aes_key);


    printf("\n");
    AES_decrypt(NULL, out, &aes_key);
    for (int i = 0; i < 16; i++) {
        printf("%x", out[i]);
    }

    return 0;
}