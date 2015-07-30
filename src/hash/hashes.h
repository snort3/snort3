//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
// hashes.h author Russ Combs <rucombs@cisco.com>

#ifndef HASHES_H
#define HASHES_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>

#ifdef HAVE_OPENSSL_SHA
#include <openssl/sha.h>
#else
#include "hash/sha2.h"
#endif

#ifdef HAVE_OPENSSL_MD5
#include <openssl/md5.h>
#else
extern "C"
{
#include "hash/md5.h"
}

typedef MD5Context MD5_CTX;

static inline int MD5_Init(MD5_CTX* c)
{ MD5Init(c); return 0; }

static inline int MD5_Update(MD5_CTX* c, const unsigned char* data, unsigned long len)
{ MD5Update(c, data, len); return 0; }

static inline int MD5_Final(unsigned char* md, MD5_CTX* c)
{ MD5Final(md, c); return 0; }
#endif

#include "main/snort_types.h"

#define MD5_HASH_SIZE    16
#define SHA256_HASH_SIZE 32
#define SHA512_HASH_SIZE 64
#define MAX_HASH_SIZE    64

// digest must be buffer of size given above
SO_PUBLIC void md5(const unsigned char* data, size_t size, unsigned char* digest);
SO_PUBLIC void sha256(const unsigned char* data, size_t size, unsigned char* digest);
SO_PUBLIC void sha512(const unsigned char* data, size_t size, unsigned char* digest);

#endif

