#ifndef AES_H
#define AES_H

#include <stdint.h>

void AES_CTR_Init( uint8_t iv, uint8_t key, uint8_t ctr );
void AES_CTR_Encode( uint8_t *plaintext, uint8_t *ciphertext, int numBytes);
void AES_CTR_Decode( uint8_t *ciphertext, uint8_t *plaintext, int numBytes);
void AES_CTR_Dump( uint8_t* data, int numBytes );

#endif // AES_H
