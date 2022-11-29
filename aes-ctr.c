#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "aes-ctr.h"

#define NUM_BITS_OF_BYTE        8       //A byte has 8 bits

static uint8_t g_IV  = 0b10110001;
static uint8_t g_Key = 0b11001011;
static uint8_t g_Ctr = 0b00110101;

static uint8_t processCtr(uint8_t, uint8_t);
static uint8_t encryptByte(uint8_t, uint8_t, uint8_t);
static uint8_t decryptByte(uint8_t, uint8_t, uint8_t);

static uint8_t getBit(uint8_t, int);
static uint8_t setBit(uint8_t, int);
static uint8_t clearBit(uint8_t, int);

/*  Function:  AES_CTR_Init
  Purpose:   Initialize AES CTR
       in:   iv - initial vector
       in:   key - key
       in:   ctr - counter
   return:   None
*/
void AES_CTR_Init( uint8_t iv, uint8_t key, uint8_t ctr )
{
    g_IV = iv;
    g_Key = key;
    g_Ctr = ctr;
}

/*  Function:  AES_CTR_Encode
  Purpose:   Encrypts the given plaintext array
       in:   array of plaintext characters
       in:   ciphertext array
       in:   number of bytes of plaintext array
   return:   None
*/
void AES_CTR_Encode(uint8_t *plaintext, uint8_t* ciphertext, int numBytes)
{
    int i = 0;
    uint8_t updated_ctr = g_Ctr, prev = 0;

    if ( plaintext != NULL && ciphertext != NULL )
    {
        /* Initial values */
        updated_ctr = processCtr( g_Ctr, g_Key );
        prev = g_IV;

        for ( i = 0; i < numBytes; i++ )
        {
            ciphertext[i] = encryptByte( plaintext[i], updated_ctr, prev );
            prev = ciphertext[i];
            updated_ctr++;
            updated_ctr = processCtr( updated_ctr, g_Key );
        }
    }
}

/*  Function:  AES_CTR_Decode
  Purpose:   Decrypts the given plaintext array
       in:   array of cipher characters
       in:   plaintext array
       in:   number of bytes of ciphertext array
   return:   None
*/
void AES_CTR_Decode (uint8_t *ciphertext, uint8_t *plaintext, int numBytes)
{
    int i = 0;
    uint8_t updated_ctr = g_Ctr, prev = 0;

    if ( plaintext != NULL && ciphertext != NULL )
    {
        /* Initial values */
        updated_ctr = processCtr( g_Ctr, g_Key );
        prev = g_IV;

        for ( i = 0; i < numBytes; i++ )
        {
            plaintext[i] = decryptByte( ciphertext[i], updated_ctr, prev );
            prev = ciphertext[i];
            updated_ctr++;
            updated_ctr = processCtr( updated_ctr, g_Key );
        }
    }
}

/*  Function:  processCtr
  Purpose:   Process Counter (CTR) byte using key
       in:   Counter value byte
       in:   key value
   return:   Updated counter value
*/
uint8_t processCtr(uint8_t ctr, uint8_t key)
{
    uint8_t i = 0, ctr_bit = 0, key_bit = 0;

    /* Make a copy of the counter value into a temporary counter */
    uint8_t tmp_ctr = ctr;
    uint8_t bit_pos = 0;

    /*  if the counter is an even number, the loop begins at bit position 0;
     *  if the counter is odd, it begins at bit position 1 */
    if ( ctr % 2 == 0 ) {
        bit_pos = 0;
    } else {
        bit_pos = 1;
    }

    for ( i = bit_pos; i < NUM_BITS_OF_BYTE; i++ )
    {
        ctr_bit = getBit( ctr, i );
        key_bit = getBit( key, i );

        /* Perform an xor operation between the current bits of the counter and of the key */
        /* Set the current bit of the temp counter to the result of this xor operation */
        if ( ctr_bit ^ key_bit ) {
            tmp_ctr = setBit( tmp_ctr, i );
        } else {
            tmp_ctr = clearBit( tmp_ctr, i );
        }

        /* Skip 1 bit */
        i++;
    }

    return tmp_ctr;
}

/*  Function:  encryptByte
  Purpose:   Encrypts the given plaintext byte
       in:   plaintext byte
       in:   counter value byte
       in:   the previous byte of the ciphertext
   return:   encrypted ciphertext byte
*/
uint8_t encryptByte(uint8_t pt, uint8_t ctr, uint8_t prev)
{
    uint8_t tmp_byte = 0, i = 0, pt_bit, prev_bit = 0, xor_ret = 0;

    for ( i = 0; i < NUM_BITS_OF_BYTE; i++ )
    {
        if ( getBit(ctr, i) == 1 ) {
            /* If the current bit of the counter is 1, perform an xor operation between the
               current bit of the plaintext and the current bit of the previous ciphertext byte */
            prev_bit = getBit( prev, i );
        } else {
            /* If the current bit of the counter is 0, perform an xor operation between the
               current bit of the plaintext and the mirror bit of the previous ciphertext byte */
            prev_bit = getBit( prev, (NUM_BITS_OF_BYTE - 1) - i );
        }
        pt_bit = getBit( pt, i );

        xor_ret = pt_bit ^ prev_bit;

        /* Set the current bit of the temp byte to the result of the xor operation above */
        if ( 1 == xor_ret ) {
            tmp_byte = setBit( tmp_byte, i );
        }
    }

    return tmp_byte;
}

/*  Function:  decryptByte
  Purpose:   Decrypts the given ciphertext byte
       in:   ciphertext byte
       in:   counter value byte
       in:   the previous byte of the ciphertext
   return:   decrypted plaintext byte
*/
uint8_t decryptByte(uint8_t ct, uint8_t ctr, uint8_t prev)
{
    uint8_t tmp_byte = 0, i = 0, ct_bit, prev_bit = 0, xor_ret = 0;

    for ( i = 0; i < NUM_BITS_OF_BYTE; i++ )
    {
        if ( getBit(ctr, i) == 1 ) {
            /* If the current bit of the counter is 1, perform an xor operation between the
               current bit of the cipher and the current bit of the previous ciphertext byte */
            prev_bit = getBit( prev, i );
        } else {
            /* If the current bit of the counter is 0, perform an xor operation between the
               current bit of the cipher and the mirror bit of the previous ciphertext byte */
            prev_bit = getBit( prev, (NUM_BITS_OF_BYTE - 1) - i );
        }
        ct_bit = getBit( ct, i );

        xor_ret = ct_bit ^ prev_bit;

        /* Set the current bit of the temp byte to the result of the xor operation above */
        if ( 1 == xor_ret ) {
            tmp_byte = setBit( tmp_byte, i );
        }
    }

    return tmp_byte;
}

/*
  Function:  getBit
  Purpose:   retrieve value of bit at specified position
       in:   character from which a bit will be returned
       in:   position of bit to be returned
   return:   value of bit n in character c (0 or 1)
*/
uint8_t getBit(uint8_t c, int n)
{
    uint8_t bit_val = 0;

    if ( n < NUM_BITS_OF_BYTE )
    {
        bit_val = (c >> n) & 0b00000001;
    }

    return bit_val;
}

/*
  Function:  setBit
  Purpose:   set specified bit to 1
       in:   character in which a bit will be set to 1
       in:   position of bit to be set to 1
   return:   new value of character c with bit n set to 1
*/
uint8_t setBit(uint8_t c, int n)
{
    uint8_t new_c = c;

    if ( n < NUM_BITS_OF_BYTE )
    {
        new_c |= (1 << n);
    }

    return new_c;
}

/*  Function:  clearBit
  Purpose:   set specified bit to 0
       in:   character in which a bit will be set to 0
       in:   position of bit to be set to 0
   return:   new value of character c with bit n set to 0
*/
uint8_t clearBit(uint8_t c, int n)
{
    uint8_t new_c = c;

    if ( n < NUM_BITS_OF_BYTE )
    {
        new_c &= ~(1 << n);
    }

    return new_c;
}

/*  Function:  AES_CTR_Dump
  Purpose:   Print data as hex
       in:   array of data characters
       in:   number of data bytes
   return:   None
*/
void AES_CTR_Dump( uint8_t* data, int numBytes )
{
    int i = 0;

    if ( data != NULL )
    {
        printf("\nData in hex:\n");
        for ( i = 0; i < numBytes; i++ )
        {
            printf("%02X ", data[i]);
        }
        printf("\n\n");
    }
}
