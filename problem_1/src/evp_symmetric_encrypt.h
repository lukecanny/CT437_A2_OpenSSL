#ifndef EVP_SYMMETRIC_ENCRYPT_H
#define EVP_SYMMETRIC_ENCRYPT_H

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
#include <unistd.h>
#include <time.h>

/*
############################################################
#                   Constant Definition                    #
############################################################
*/

/* 100MB (10485760 for 10MB) */
#define BUFFER_SIZE 104857600   

/*
############################################################
#                   Function Prototypes                    #
############################################################
*/
int execute(const EVP_CIPHER * cipher_mode, unsigned char * plaintext, unsigned char * key,
            unsigned char * iv);

void handleErrors(void);

int encrypt(unsigned char * plaintext, int plaintext_len, unsigned char * key,
            unsigned char * iv, unsigned char * ciphertext, const EVP_CIPHER * cipher_mode,
            unsigned char *tag);

int decrypt(unsigned char * ciphertext, int ciphertext_len, unsigned char * key,
            unsigned char * iv, unsigned char * plaintext, const EVP_CIPHER * cipher_mode,
            unsigned char * tag);

#endif