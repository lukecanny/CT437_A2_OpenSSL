#include "evp_symmetric_encrypt.h"

/*  Determine and constrast CPU time of the following encryption settings:
 *       AES, ARIA and Camellia Algorithm    
 *       128 and 256 key length              
 *       ECB, CBC and GCM mode               
 *       10MB and 100MB of data              
 *       encoding and decoding               
*/
int main (void)
{

    unsigned char *key256 = (unsigned char *)"01234567890123456789012345678901";   // 256 bit key
    unsigned char *key128 = (unsigned char *)"0123456789012345";                   // 128 bit key

    unsigned char *iv128 = (unsigned char *)"0123456789012345";                    // 128 bit IV

    /* The following block of code is to generate 10 or 100 MB of random text data for benchmarking purposes */
    unsigned char *plaintext = (char*) malloc (BUFFER_SIZE);
    const unsigned char charset[] = "abcdefhijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0987654321";
    const size_t charsetSize = sizeof(charset) - 1;
    for (size_t i = 0; i < BUFFER_SIZE; ++i){
        plaintext[i] = charset[rand() % charsetSize];
    }
    plaintext[BUFFER_SIZE-1] = '\0';

    /* 
     * The first results produced are when program starts are excessively high for any 
     * algorithm, therefore we discard the first 3 recordings 
     */
    int retVal;
    for (int i = 0; i < 3; i++)
        retVal = execute((const EVP_CIPHER *) EVP_aes_256_cbc(), plaintext, key256, iv128);
    printf("\nTestStart");
    
    /* For each configuration, run the execute (benchmarking) function 100 times */

    /* AES */
    printf("\nAES_128_CBC");
    for (int i = 0; i < 100; i++)
        retVal = execute((const EVP_CIPHER *) EVP_aes_128_cbc(), plaintext, key128, iv128);
    printf("\nAES_128_ECB");
    for (int i = 0; i < 100; i++)
        retVal = execute((const EVP_CIPHER *) EVP_aes_128_ecb(), plaintext, key128, iv128);
    printf("\nAES_128_GCM");
    for (int i = 0; i < 100; i++)
        retVal = execute((const EVP_CIPHER *) EVP_aes_128_gcm(), plaintext, key128, iv128);
    printf("\nAES_256_CBC");
    for (int i = 0; i < 100; i++)
        retVal = execute((const EVP_CIPHER *) EVP_aes_256_cbc(), plaintext, key256, iv128);
    printf("\nAES_256_ECB");
    for (int i = 0; i < 100; i++)
        retVal = execute((const EVP_CIPHER *) EVP_aes_256_ecb(), plaintext, key256, iv128);
    printf("\nAES_256_GCM");
    for (int i = 0; i < 100; i++)
        retVal = execute((const EVP_CIPHER *) EVP_aes_256_gcm(), plaintext, key256, iv128);
    
    /* ARIA */
    printf("\nARIA_128_CBC");
    for (int i = 0; i < 100; i++)
        retVal = execute((const EVP_CIPHER *) EVP_aria_128_cbc(), plaintext, key128, iv128);
    printf("\nARIA_128_ECB");
    for (int i = 0; i < 100; i++)
        retVal = execute((const EVP_CIPHER *) EVP_aria_128_ecb(), plaintext, key128, iv128);
    printf("\nARIA_128_GCM");
    for (int i = 0; i < 100; i++)
        retVal = execute((const EVP_CIPHER *) EVP_aria_128_gcm(), plaintext, key128, iv128);
    printf("\nARIA_256_CBC");
    for (int i = 0; i < 100; i++)
        retVal = execute((const EVP_CIPHER *) EVP_aria_256_cbc(), plaintext, key256, iv128);
    printf("\nARIA_256_ECB");
    for (int i = 0; i < 100; i++)
        retVal = execute((const EVP_CIPHER *) EVP_aria_256_ecb(), plaintext, key256, iv128);
    printf("\nARIA_256_GCM");
    for (int i = 0; i < 100; i++)
        retVal = execute((const EVP_CIPHER *) EVP_aria_256_gcm(), plaintext, key256, iv128);

    /* Camellia */
    printf("\nCamellia_128_CBC");
    for (int i = 0; i < 100; i++)
        retVal = execute((const EVP_CIPHER *) EVP_camellia_128_cbc(), plaintext, key128, iv128);
    printf("\nCamellia_128_ECB");
    for (int i = 0; i < 100; i++)
        retVal = execute((const EVP_CIPHER *) EVP_camellia_128_ecb(), plaintext, key128, iv128);
    printf("\nCamellia_256_CBC");
    for (int i = 0; i < 100; i++)
        retVal = execute((const EVP_CIPHER *) EVP_camellia_256_cbc(), plaintext, key256, iv128);
    printf("\nCamellia_256_ECB");
    for (int i = 0; i < 100; i++)
        retVal = execute((const EVP_CIPHER *) EVP_camellia_256_ecb(), plaintext, key256, iv128);

    /* Free Memory */
    free(plaintext);

}

int execute (const EVP_CIPHER * cipher_mode, unsigned char * plaintext, unsigned char * key, unsigned char * iv)
{

    /* Buffer for ciphertext. */
    unsigned char *ciphertext = (unsigned char*)malloc(BUFFER_SIZE+16);

    /* Buffer for the decrypted text */
    unsigned char *decryptedtext = (unsigned char*)malloc(BUFFER_SIZE);

    /* Buffer for Authentication Tag (GCM) */
    unsigned char *tag = (unsigned char*)malloc(16);

    /* Plaintext / Ciphertext Length */
    int decryptedtext_len, ciphertext_len;

    /* Struct for Time Recordings */
    struct timespec en_time_start, en_time_end, de_time_start, de_time_end;

    // Record start encryption time:
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &en_time_start);
    /* Encrypt the plaintext */
    ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), key, iv,
                              ciphertext, cipher_mode, tag);
    // Record end encryption time:
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &en_time_end);

    // /* Print the Ciphertext */
    // printf("Ciphertext is:\n");
    // BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    // Begin recording decryption time:
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &de_time_start);
    /* Decrypt the ciphertext */
    decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv,
                                decryptedtext, cipher_mode, tag);
    // Finish recording decryption time:
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &de_time_end);

    // /* Add a NULL terminator. We are expecting printable text */
    // decryptedtext[decryptedtext_len] = '\0';

    // /* Show the decrypted text */
    // printf("Decrypted text is:\n");
    // printf("%s\n", decryptedtext);

    /* Calculate the Encryption and Decryption times */
    double encryption_time = (en_time_end.tv_sec - en_time_start.tv_sec) +
                          (en_time_end.tv_nsec - en_time_start.tv_nsec) / 1e9;

    double decryption_time = (de_time_end.tv_sec - de_time_start.tv_sec) +
                          (de_time_end.tv_nsec - de_time_start.tv_nsec) / 1e9;

    /* Print results in CSV format (encrypt, decrypt)*/
    printf("\n%f, %f", encryption_time, decryption_time);

    /* Free Memory */
    free(ciphertext);
    free(decryptedtext);

    return 0;
}


void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext, const EVP_CIPHER *cipher_mode,
            unsigned char * tag)
{
    /* Create Cipher Context */
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

    /* 
     * Store the Authentication Tag. Applies only for GCM mode.
     * Used to decrypt, stored in tag variable.
    */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) 
        handleErrors();

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}


int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext, const EVP_CIPHER * cipher_mode,
            unsigned char * tag)
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
     * Set the Authentication Tag. Applies only for GCM mode.
     * Tag was stored when encrypting.
    */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) 
        handleErrors();

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
