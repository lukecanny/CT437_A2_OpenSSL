#include "evp_symmetric_encrypt.h"

/*  Determine and constrast CPU time of the following encryption settings:
        AES, ARIA and Camellia Algorithm    * 3
        128 and 256 key length              * 2
        ECB, CBC and GCM mode               * 3
        10MB and 100MB of data              * 2
        encoding and decoding               * 2 = 72 configurations (Some configurations not covered by Camellia ~ 32 total)
*/
int main (void)
{

    // int key_lengths[] = {128, 256};
    // const char *algorithms[] = {"AES", "ARIA", "Camellia"};
    unsigned char *key256 = (unsigned char *)"01234567890123456789012345678901";   // 256 bit key
    unsigned char *key128 = (unsigned char *)"0123456789012345";                   // 128 bit key

    unsigned char *iv128 = (unsigned char *)"0123456789012345";                    // 128 bit IV
    unsigned char *iv96 = (unsigned char *)"012345678901";                         // 96 bit IV (for GCM mode)

    unsigned char *plaintext = (unsigned char *)"The quick brown fox jumps over the lazy dog";

    int retVal;
    // for (int i = 0; i < 3; i++)
    //     retVal = execute((const EVP_CIPHER *) EVP_aes_256_cbc(), plaintext, key256, iv128);
    // printf("\nTestStart");


    // // AES
    // printf("\nAES_256_CBC");
    // for (int i = 0; i < 100; i++)
    //     retVal = execute((const EVP_CIPHER *) EVP_aes_256_cbc(), plaintext, key256, iv128);
    // printf("\nAES_256_ECB");
    // for (int i = 0; i < 100; i++)
    //     retVal = execute((const EVP_CIPHER *) EVP_aes_256_ecb(), plaintext, key256, iv128);
    printf("\nAES_256_GCM");
    for (int i = 0; i < 100; i++)
        retVal = execute((const EVP_CIPHER *) EVP_aes_256_gcm(), plaintext, key256, iv96);
    // ARIA
    printf("\nARIA_256_CBC");

    printf("\nARIA_256_ECB");

    printf("\nARIA_256_GCM");

    

}

int execute (const EVP_CIPHER * cipher_mode, unsigned char * plaintext, unsigned char * key, unsigned char * iv)
{

    // unsigned char *key   - Define a "pointer" called key of type "unsigned char" 
    // (unsigned char *)    - Type cast the literal string into unsigned char pointer
    // char are normally 8-bits i.e. -128 to 127, unsigned makes range 0-255.

    // What I dont understand:
        // the string "01234567890123456789012345678901" is obviously much bigger
        // What does unsigned char * as a type cast mean
    /* Cipher Mode */
    //const EVP_CIPHER * cipher_mode = EVP_aes_256_cbc();

    /* A 256 bit key */
    // unsigned char *key = (unsigned char *)"01234567890123456789012345678901";

    /* A 128 bit IV */
    // unsigned char *iv = (unsigned char *)"0123456789012345";
    // 012345678901

    /* Message to be encrypted */
    // unsigned char *plaintext =
    //     (unsigned char *)"The quick brown fox jumps over the lazy dog";

    /* Buffer for ciphertext. */
    unsigned char ciphertext[128];

    /* Buffer for the decrypted text */
    unsigned char decryptedtext[128];

    /* Plaintext / Ciphertext Length */
    int decryptedtext_len, ciphertext_len;

    /* Struct for Time Recordings */
    struct timespec en_time_start, en_time_end, de_time_start, de_time_end;

    // Record start encryption time:
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &en_time_start);
    /* Encrypt the plaintext */
    ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), key, iv,
                              ciphertext, cipher_mode);
    // Record end encryption time:
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &en_time_end);

    // /* Do something useful with the ciphertext here */
    // printf("Ciphertext is:\n");
    // BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    // Begin recording decryption time:
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &de_time_start);
    /* Decrypt the ciphertext */
    decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv,
                                decryptedtext, cipher_mode);
    // Finish recording decryption time:
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &de_time_end);

    // /* Add a NULL terminator. We are expecting printable text */
    // decryptedtext[decryptedtext_len] = '\0';

    // /* Show the decrypted text */
    // printf("Decrypted text is:\n");
    // printf("%s\n", decryptedtext);
    double encryption_time = (en_time_end.tv_sec - en_time_start.tv_sec) +
                          (en_time_end.tv_nsec - en_time_start.tv_nsec) / 1e9;

    double decryption_time = (de_time_end.tv_sec - de_time_start.tv_sec) +
                          (de_time_end.tv_nsec - de_time_start.tv_nsec) / 1e9;

    printf("\n%f, %f", encryption_time, decryption_time);
    return 0;
}


void handleErrors(void)
{
    ERR_print_errors_fp(stdout);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext, const EVP_CIPHER *cipher_mode)
{

    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, cipher_mode, NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}


int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext, const EVP_CIPHER * cipher_mode)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, cipher_mode, NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}
