/*
 * Copyright (c) 2018, mod0keecrack
 *    William Brawner <billybrawner at gmail dot com>
 *
 * All rights reserved.
 *
 * This file is part of mod0keecrack.
 *
 * "THE BEER-WARE LICENSE" (Revision 42):
 * William Brawner <billybrawner at gmail dot com> wrote this file. As long as you
 * retain this notice you can do whatever you want with this stuff. If we meet
 * some day, and you think this stuff is worth it, you can buy me a beer in
 * return. William Brawner.
 *
 * NON-MILITARY-USAGE CLAUSE
 * Redistribution and use in source and binary form for military use and
 * military research is not permitted. Infringement of these clauses may
 * result in publishing the source code of the utilizing applications and
 * libraries to the public. As this software is developed, tested and
 * reviewed by *international* volunteers, this clause shall not be refused
 * due to the matter of *national* security concerns.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE DDK PROJECT BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * File: crypto-openssl.c
 * Description: Platform specific implementation of keepassx crypto functions
 *              on Linux
 */

#include <stdio.h>
#include <openssl/blowfish.h>
#include <openssl/evp.h>
#include <stdbool.h>

#include "helper.h"
#include "mod0keecrack.h"


int aes_transformkey(m0_kdbx_header_entry_t *hdr, uint8_t *tkey, size_t tkeylen) 
{
  uint64_t          rounds         = 0;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

  EVP_EncryptInit_ex(
          ctx,
          EVP_aes_128_ecb(),
          NULL,
          key,
          NULL);

  EVP_EncryptUpdate(
          ctx,
          NULL,
          0,
          tkey,
          tkeylen);


  for(rounds = 0; rounds < hdr[TRANSFORMROUNDS].qw; rounds++) {
  }

cleanup:
  if (ctx) {
      EVP_CIPHER_CTX_free(ctx);
  }
}

bool aes_decrypt_check(m0_kdbx_header_entry_t *hdr, uint8_t *masterkey, m0_kdbx_payload_t *p) {

}

int sha256_hash(uint8_t *hash, uint8_t *data, size_t len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    EVP_DigestInit(
            ctx, 
            EVP_sha256()
            );

    EVP_DigestUpdate(
            ctx, 
            data, 
            len
            );

    EVP_DigestFinal(
            ctx, 
            hash, 
            NULL
            );

    return 0;
}
