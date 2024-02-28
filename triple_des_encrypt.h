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




#endif