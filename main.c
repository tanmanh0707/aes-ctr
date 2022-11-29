#include <stdio.h>
#include <string.h>
#include "aes-ctr.h"

#define IV  0b10110001
#define KEY 0b11001011
#define CTR 0b00110101

#define MAX_BUF  256

int main()
{
    unsigned char plaintext[MAX_BUF];
    unsigned char ciphertext[MAX_BUF];
    unsigned char result[MAX_BUF];

    memset(plaintext, 0, MAX_BUF);
    memset(ciphertext, 0, MAX_BUF);
    memset(result, 0, MAX_BUF);

    strcpy((char*)plaintext, "Hello World!!!\n");

    AES_CTR_Init( IV, KEY, CTR );

    AES_CTR_Encode( plaintext, ciphertext, strlen((char*)plaintext));
    AES_CTR_Dump(ciphertext, strlen((char*)plaintext));
    AES_CTR_Decode( ciphertext, result, strlen((char*)ciphertext));
    printf("%s\n", result);

    return 0;
}
