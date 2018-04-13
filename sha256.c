/*
 * =====================================================================================
 *
 *       Filename:  sha256.c
 *
 *    Description:  An OpenSSL SHA256 Utility
 *
 *        Version:  1.0
 *        Created:  04/03/2018 06:13:41 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  William Brawner (Billy), billybrawner@gmail.com
 *   Organization:  
 *
 * =====================================================================================
 */
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>
#include "helper.h"

int main(int argc, char ** argv) {
    if (argc < 2) {
        printf("Please enter a string to hash\n");
        return 1;
    }

    printf("You entered %s\n", argv[1]);
    printf("Your string contains %d characters\n", strlen(argv[1]));

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit(ctx, EVP_sha256());
    EVP_DigestUpdate(ctx, argv[1], strlen(argv[1]));
    char* hash = malloc(EVP_MD_CTX_size(ctx));
    EVP_DigestFinal(ctx, hash, NULL);
    printf("Your hashed string: ");
    print_hex_buf(hash, 32);
    printf("\n");
}
