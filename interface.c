#include "main.h"
#include <stdio.h>

void addRoundKey(const unsigned char *in, unsigned char *key, unsigned char *out) {
    uint32_t s[4], k[4];
    s[0] = GETU32(in     );
    s[1] = GETU32(in +  4);
    s[2] = GETU32(in +  8);
    s[3] = GETU32(in + 12);

    k[0] = GETU32(key     );
    k[1] = GETU32(key +  4);
    k[2] = GETU32(key +  8);
    k[3] = GETU32(key + 12);

    *(uint32_t*)(out+0) = s[0] ^ k[0];
    *(uint32_t*)(out+4) = s[1] ^ k[1];
    *(uint32_t*)(out+8) = s[2] ^ k[2];
    *(uint32_t*)(out+12) = s[3] ^ k[3];
}

void shiftRows(const unsigned char *in, unsigned char *out) {
    uint32_t t[4];
    t[0] = GETU32(in     );
    t[1] = GETU32(in +  4);
    t[2] = GETU32(in +  8);
    t[3] = GETU32(in + 12);

    *(uint32_t*)(out+0) = ((t[0]) & 0xff) ^
                          ((t[1] >> 8) & 0xff) << 8 ^
                          ((t[2] >> 16) & 0xff) << 16 ^
                          ((t[3] >> 24)) << 24;
    *(uint32_t*)(out+4) = ((t[1]) & 0xff) ^
                          ((t[2] >> 8) & 0xff) << 8 ^
                          ((t[3] >> 16) & 0xff) << 16 ^
                          ((t[0] >> 24)) << 24;

    printf("%x", *(uint32_t*)(out+4));

    *(uint32_t*)(out+8) = ((t[2]) & 0xff) ^
                          ((t[3] >> 8) & 0xff) << 8 ^
                          ((t[0] >> 16) & 0xff) << 16 ^
                          ((t[1] >> 24)) << 24;
    *(uint32_t*)(out+12) = ((t[3]) & 0xff) ^
                           ((t[0] >> 8) & 0xff) << 8 ^
                           ((t[1] >> 16) & 0xff) << 16 ^
                           ((t[2] >> 24)) << 24;
}

void mixColumns(const unsigned char *in, unsigned char *out) {
    uint32_t s[4];
    s[0] = GETU32(in     );
    s[1] = GETU32(in +  4);
    s[2] = GETU32(in +  8);
    s[3] = GETU32(in + 12);

    int i;
    uint32_t r0, r1, r2;

    for (i = 0; i < 4; i++) {
        r0 = s[i];
        r1 = r0 & 0x80808080;
        // 低7位左移, 进行模除
        r2 = ((r0 & 0x7f7f7f7f) << 1) ^
             ((r1 - (r1 >> 7)) & 0x1b1b1b1b);
        *(uint32_t*)(out+i*4) = r2 ^ ROTATE(r2, 24) ^ ROTATE(r0, 24) ^
               ROTATE(r0, 16) ^ ROTATE(r0, 8);
    }
}

void subBytes(const unsigned char *in, unsigned char *out) {
    uint32_t s[4];
    s[0] = GETU32(in     );
    s[1] = GETU32(in +  4);
    s[2] = GETU32(in +  8);
    s[3] = GETU32(in + 12);

    *(uint32_t*)(out+0)  = (uint32_t) Te4[(s[0]) & 0xff] ^
                           (uint32_t) Te4[(s[0] >> 8) & 0xff] << 8 ^
                           (uint32_t) Te4[(s[0] >> 16) & 0xff] << 16 ^
                           (uint32_t) Te4[(s[0] >> 24)] << 24;
    *(uint32_t*)(out+4)  = (uint32_t) Te4[(s[1]) & 0xff] ^
                           (uint32_t) Te4[(s[1] >> 8) & 0xff] << 8 ^
                           (uint32_t) Te4[(s[1] >> 16) & 0xff] << 16 ^
                           (uint32_t) Te4[(s[1] >> 24)] << 24;
    *(uint32_t*)(out+8)  = (uint32_t) Te4[(s[2]) & 0xff] ^
                           (uint32_t) Te4[(s[2] >> 8) & 0xff] << 8 ^
                           (uint32_t) Te4[(s[2] >> 16) & 0xff] << 16 ^
                           (uint32_t) Te4[(s[2] >> 24)] << 24;
    *(uint32_t*)(out+12) = (uint32_t) Te4[(s[3]) & 0xff] ^
                           (uint32_t) Te4[(s[3] >> 8) & 0xff] << 8 ^
                           (uint32_t) Te4[(s[3] >> 16) & 0xff] << 16 ^
                           (uint32_t) Te4[(s[3] >> 24)] << 24;
}


void encrypt_file(char* in, char* out, AES_KEY* aes_key, char* result) {
    // remove the output file if it exists
    remove(out);

    FILE *file;
    FILE *file_output;

    file = fopen(in, "rb");

    if (file == NULL) {
        sprintf(result, "Cannot open file");
        return;
    }

    file_output = fopen(out, "wb");

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    uint64_t size_low = (uint64_t)file_size;
    uint64_t size_high = size_low >> 61;
    size_low <<= 3;
    unsigned char size[16] = {0};
    size[ 7] = (unsigned char)size_high;
    size[ 8] = (unsigned char) (size_low >> 56)        ;
    size[ 9] = (unsigned char)((size_low >> 48) & 0xff);
    size[10] = (unsigned char)((size_low >> 40) & 0xff);
    size[11] = (unsigned char)((size_low >> 32) & 0xff);
    size[12] = (unsigned char)((size_low >> 24) & 0xff);
    size[13] = (unsigned char)((size_low >> 16) & 0xff);
    size[14] = (unsigned char)((size_low >>  8) & 0xff);
    size[15] = (unsigned char)((size_low      ) & 0xff);

    fseek(file, 0, SEEK_SET);

    unsigned char size_encrypted[16];
    AES_encrypt_file(size, size_encrypted, aes_key);

    fwrite(size_encrypted, 1, 16, file_output);
    fwrite(size_encrypted, 1, 16, file_output);
    fwrite(size_encrypted, 1, 16, file_output);

    ssize_t n;
    unsigned char content[16], content_encrypted[16];

    while ((n = fread(&content, 1, 16, file)) > 0) {
        if (n < 16) {
            // fill zeros
            for (int i = (int)n; i < 16; i++) {
                content[i] = 0;
            }
        }

        // change the order
        AES_encrypt_file(content, content_encrypted, aes_key);

        fwrite(&content_encrypted, 1, 16, file_output);
    }

    fclose(file);
    fclose(file_output);
}

uint8_t char2num(char ch) {
    if (ch >= 48 && ch <= 57) {
        // 数字
        return (uint8_t)(ch - 48);
    } else if (ch >= 97 && ch <= 102) {
        // 小写字母
        return (uint8_t)(ch - 87);
    } else if (ch >= 65 && ch <= 70) {
        // 大写字母
        return (uint8_t)(ch - 55);
    }  else {
        printf("input error\n");
        return (uint8_t)-1;
    }
}

void decrypt_file(char* in, char* out, AES_KEY* aes_key, char* result) {
    remove(out);

    // Define the files and then open them
    FILE *file;
    FILE *file_output;
    file = (fopen(in, "rb"));

    long filesize;

    if (file == NULL) {
        sprintf(result, "Cannot open file");
        return;
    }

    // get file size
    fseek(file, 0, SEEK_END);
    filesize = ftell(file);

    fseek(file, 0, SEEK_SET);

    unsigned char flag1[16], flag2[16], flag3[16], flag_d1[16], flag_d2[16], flag_d3[16];
    fread(&flag1, 1, 16, file);
    fread(&flag2, 1, 16, file);
    fread(&flag3, 1, 16, file);

    AES_decrypt_file(flag1, flag_d1, aes_key);
    AES_decrypt_file(flag2, flag_d2, aes_key);
    AES_decrypt_file(flag3, flag_d3, aes_key);

    uint64_t length1 = 0;
    for (int i = 0; i < 8; i++) {
        length1 <<= 8;
        length1 |= flag_d1[i + 8];
    }
    length1 >>= 3;
    length1 |= ((uint64_t)(flag_d1[7] & 0x7)) << 61;

    uint64_t length2 = 0;
    for (int i = 0; i < 8; i++) {
        length2 <<= 8;
        length2 |= flag_d2[i + 8];
    }
    length2 >>= 3;
    length2 |= ((uint64_t)(flag_d2[7] & 0x7)) << 61;

    uint64_t length3 = 0;
    for (int i = 0; i < 8; i++) {
        length3 <<= 8;
        length3 |= flag_d3[i + 8];
    }
    length3 >>= 3;
    length3 |= ((uint64_t)(flag_d3[7] & 0x7)) << 61;

    uint64_t length;

    if (length1 == length2 || length1 == length3) {
        length = length1;
    } else if (length2 == length3){
        length = length2;
    } else {
        sprintf(result, "Voting failed");
        return;
    }


    uint64_t len = length;
    uint64_t remain = (16 - len % 16) % 16;

    if (len + 48 + remain != filesize) {
        sprintf(result, "Invalid encrypting format");
        return;
    }

    uint64_t unit_len = len / 16;
    uint8_t unit_len_extra = (uint8_t)(len % 16);

    file_output = fopen(out, "wb");

    unsigned char content[16], content_decrypted[16];
    for (uint64_t i = 0; i < unit_len; i++) {
        fread(&content, 1, 16, file);

        AES_decrypt_file(content, content_decrypted, aes_key);

        fwrite(&content_decrypted, 1, 16, file_output);
    }

    unsigned char content_decoded_16[16];
    fread(&content, 1, 16, file);

    AES_decrypt_file(content, content_decoded_16, aes_key);

    for (uint8_t i = 0; i < unit_len_extra; i++) {
        fwrite(&content_decoded_16[i], 1, 1, file_output);
    }

    fclose(file);
    fclose(file_output);
}