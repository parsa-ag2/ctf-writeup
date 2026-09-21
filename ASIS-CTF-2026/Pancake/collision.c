#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>

int main(void)
{
    unsigned char key[32] = {
        0xe9, 0xd1, 0x34, 0xee, 0x04, 0x8c, 0xf7, 0xee,
        0x51, 0x94, 0x46, 0xc8, 0xcf, 0x25, 0xe9, 0xe4,
        0xcb, 0xe6, 0x2e, 0x93, 0x40, 0x7b, 0x65, 0xe9,
        0xe9, 0xee, 0x4b, 0x8f, 0xa1, 0x00, 0xe3, 0xd0
    };
    unsigned char n2[12] = {
        0x43, 0x12, 0x63, 0xc0, 0x38, 0x2f,
        0xe1, 0xa1, 0x10, 0x6a, 0x9e, 0x2d
    };
    unsigned char in[16] = {0}, out[16];
    int len;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    memcpy(in, n2, 12);
    EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_EncryptUpdate(ctx, out, &len, in, 16);
    memcpy(in, out, 12);

    EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    for (uint64_t sep = 0; sep < (1ULL << 32); sep++) {
        for (int i = 0; i < 4; i++)
            in[12 + i] = sep >> (24 - 8 * i);
        EVP_DecryptUpdate(ctx, out, &len, in, 16);

        if (!(out[12] | out[13] | out[14] | out[15]) && memcmp(out, n2, 12)) {
            printf("alt = ");
            for (int i = 0; i < 12; i++)
                printf("%02x", out[i]);
            printf("\n");
            break;
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}