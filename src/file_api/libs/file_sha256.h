/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 ** Copyright (C) 2012-2013 Sourcefire, Inc.
 **
 **
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License Version 2 as
 ** published by the Free Software Foundation.  You may not use, modify or
 ** distribute this program under any other version of the GNU General
 ** Public License.
 **
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 ** GNU General Public License for more details.
 **
 ** You should have received a copy of the GNU General Public License
 ** along with this program; if not, write to the Free Software
 ** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 **
 ** The code is based on DotGNU Portable.NET GPL
 ** 5/1/2012 - Initial implementation ... Hui Cao <hcao@sourcefire.com>
 */

#ifndef FILE_SHA256_H
#define FILE_SHA256_H

#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "snort_types.h"

#define SHA256_HASH_SIZE  64

#ifdef HAVE_OPENSSL_SHA
#include <openssl/sha.h>
#define SHA256CONTEXT SHA256_CTX
#define SHA256INIT    SHA256_Init  // FIXTHIS these are deprecated
#define SHA256UPDATE  SHA256_Update
#define SHA256FINAL   SHA256_Final
#else
typedef struct _Sha256Context
{
    uint32_t inputLen;
    uint32_t A, B, C, D, E, F, G, H;
    uint8_t input[64];
    uint64_t totalLen;
}Sha256Context;
void SHA256Init(Sha256Context *sha);
void SHA256ProcessData(Sha256Context *sha, const void *buffer, unsigned long len);
void SHA256Final(unsigned char *hash, Sha256Context *sha);

#define SHA256CONTEXT Sha256Context
#define SHA256INIT    SHA256Init
#define SHA256UPDATE  SHA256ProcessData
#define SHA256FINAL   SHA256Final
#endif

#endif /* SFSHA256_H */

