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

// Define CLOCK_PROCESS_CPUTIME_ID for IntelliSense only
#ifndef CLOCK_PROCESS_CPUTIME_ID
#define CLOCK_PROCESS_CPUTIME_ID 15
#endif

// #define BUFFER_SIZE 10485760    // 10mb
#define BUFFER_SIZE 104857600   // 100MB
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