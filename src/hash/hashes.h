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

#ifndef HASHES_H
#define HASHES_H

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

