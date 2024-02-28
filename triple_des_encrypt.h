#ifndef TRIPLE_DES_ENCRYPT_H
#define TRIPLE_DES_ENCRYPT_H

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

#define BUFFER_SIZE 104857600 // 100 MB Block Size

// Define CLOCK_PROCESS_CPUTIME_ID for IntelliSense only
#ifndef CLOCK_PROCESS_CPUTIME_ID
#define CLOCK_PROCESS_CPUTIME_ID 15
#endif

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