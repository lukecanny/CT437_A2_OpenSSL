#ifndef evp_symmetric_encrypt_h
#define evp_symmetric_encrypt_h

/*
############################################################
#                      Header Includes                     #
############################################################
*/
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/*
############################################################
#                   Function Prototypes                    #
############################################################
*/
void handleErrors(void);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);



#endif