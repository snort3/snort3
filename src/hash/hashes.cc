//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
// hashes.h author Alexandre Guerlach <grlch.alexandre@proton.me>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "hashes.h"

#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <string.h>

namespace snort
{
void sha256(const unsigned char *data, size_t size, unsigned char *digest) {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len, i;

    mdctx = EVP_MD_CTX_new();

    md = EVP_sha256();
    if (!md) {
        printf("Unknow algorithm\n");
        EVP_MD_CTX_free(mdctx);
        exit(1);
    }

    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
        printf("Erreur : Initialisation du hachage échouée.\n");
        EVP_MD_CTX_free(mdctx);
        exit(1);
    }

    if (EVP_DigestUpdate(mdctx, data, size) != 1) {
        printf("Message digest update failed.\n");
        EVP_MD_CTX_free(mdctx);
        exit(1);
    }

    if (EVP_DigestFinal_ex(mdctx, md_value, &md_len) != 1) {
        printf("Message digest finalization failed.\n");
        EVP_MD_CTX_free(mdctx);
        exit(1);
    }

    memcpy(digest, md_value, md_len);
    EVP_MD_CTX_free(mdctx);
}

void sha512(const unsigned char *data, size_t size, unsigned char *digest) {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len, i;

    mdctx = EVP_MD_CTX_new();

    md = EVP_sha512();
    if (!md) {
        printf("Unknow algorithm\n");
        EVP_MD_CTX_free(mdctx);
        exit(1);
    }

    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
        printf("Erreur : Initialisation du hachage échouée.\n");
        EVP_MD_CTX_free(mdctx);
        exit(1);
    }

    if (EVP_DigestUpdate(mdctx, data, size) != 1) {
        printf("Message digest update failed.\n");
        EVP_MD_CTX_free(mdctx);
        exit(1);
    }

    if (EVP_DigestFinal_ex(mdctx, md_value, &md_len) != 1) {
        printf("Message digest finalization failed.\n");
        EVP_MD_CTX_free(mdctx);
        exit(1);
    }

    memcpy(digest, md_value, md_len);
    EVP_MD_CTX_free(mdctx);
}

void md5(const unsigned char *data, size_t size, unsigned char *digest) {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len, i;

    mdctx = EVP_MD_CTX_new();

    md = EVP_md5();
    if (!md) {
        printf("Unknow algorithm\n");
        EVP_MD_CTX_free(mdctx);
        exit(1);
    }

    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
        printf("Erreur : Initialisation du hachage échouée.\n");
        EVP_MD_CTX_free(mdctx);
        exit(1);
    }

    if (EVP_DigestUpdate(mdctx, data, size) != 1) {
        printf("Message digest update failed.\n");
        EVP_MD_CTX_free(mdctx);
        exit(1);
    }

    if (EVP_DigestFinal_ex(mdctx, md_value, &md_len) != 1) {
        printf("Message digest finalization failed.\n");
        EVP_MD_CTX_free(mdctx);
        exit(1);
    }

    memcpy(digest, md_value, md_len);
    EVP_MD_CTX_free(mdctx);
}
}