//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "hashes.h"

#include <openssl/md5.h>
#include <openssl/sha.h>

namespace snort
{
void sha256(const unsigned char* data, size_t size, unsigned char* digest)
{
    SHA256_CTX c;
    SHA256_Init(&c);
    SHA256_Update(&c, data, size);
    SHA256_Final(digest, &c);
}

void sha512(const unsigned char* data, size_t size, unsigned char* digest)
{
    SHA512_CTX c;
    SHA512_Init(&c);
    SHA512_Update(&c, data, size);
    SHA512_Final(digest, &c);
}

void md5(const unsigned char* data, size_t size, unsigned char* digest)
{
    MD5_CTX c;
    MD5_Init(&c);
    MD5_Update(&c, data, size);
    MD5_Final(digest, &c);
}

}
