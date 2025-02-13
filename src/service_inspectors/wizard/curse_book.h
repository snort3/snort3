//--------------------------------------------------------------------------
// Copyright (C) 2023-2025 Cisco and/or its affiliates. All rights reserved.
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
// curse_book.h author Maya Dagon <mdagon@cisco.com>
// Refactored from curse.h

#ifndef CURSE_BOOK_H
#define CURSE_BOOK_H

#include <cstdint>
#include <string>
#include <vector>

#include "dce_curse.h"
#include "mms_curse.h"
#include "s7commplus_curse.h"
#include "ssl_curse.h"

class CurseTracker
{
public:
    DceTracker dce;
    MmsTracker mms;
    S7commplusTracker s7commplus;
    SslTracker ssl;
};

typedef bool (* curse_alg)(const uint8_t* data, unsigned len, CurseTracker*);

struct CurseDetails
{
    std::string name;
    const char* service;
    curse_alg alg;
    bool is_tcp;
};

class CurseBook
{
public:
    bool add_curse(const char* service);
    const std::vector<const CurseDetails*>& get_curses(bool tcp) const;

private:
    std::vector<const CurseDetails*> tcp_curses;
    std::vector<const CurseDetails*> non_tcp_curses;
    static std::vector<CurseDetails> curse_map;

    static bool dce_udp_curse(const uint8_t* data, unsigned len, CurseTracker*);
    static bool dce_tcp_curse(const uint8_t* data, unsigned len, CurseTracker*);
    static bool dce_smb_curse(const uint8_t* data, unsigned len, CurseTracker*);
    static bool mms_curse(const uint8_t* data, unsigned len, CurseTracker*);
    static bool s7commplus_curse(const uint8_t* data, unsigned len, CurseTracker*);
#ifdef CATCH_TEST_BUILD
public:
#endif
    static bool ssl_v2_curse(const uint8_t* data, unsigned len, CurseTracker*);
};

#endif
