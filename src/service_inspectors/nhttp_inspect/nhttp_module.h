//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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
// nhttp_module.h author Tom Peters <thopeter@cisco.com>

#ifndef NHTTP_MODULE_H
#define NHTTP_MODULE_H

#include <string>
#include <bitset>

#include "framework/module.h"

#include "nhttp_enum.h"

#define NHTTP_NAME "new_http_inspect"
#define NHTTP_HELP "new HTTP inspector"

struct NHttpParaList
{
public:
    long request_depth;
    long response_depth;
    bool unzip;
    struct UriParam
    {
    public:
        UriParam();
        ~UriParam() { delete[] unicode_map; }

        bool percent_u = false;
        bool utf8 = true;
        bool utf8_bare_byte = false;
        bool iis_unicode = false;
        std::string iis_unicode_map_file;
        int iis_unicode_code_page = 1252;
        uint8_t* unicode_map = nullptr;
        bool iis_double_decode = false;
        bool backslash_to_slash = false;
        bool plus_to_space = true;
        bool simplify_path = true;
        std::bitset<256> bad_characters;
        std::bitset<256> unreserved_char;
        NHttpEnums::CharAction uri_char[256];
    };
    UriParam uri_param;
#ifdef REG_TEST
    bool test_input;
    bool test_output;
    long print_amount;
    bool print_hex;
    bool show_pegs;
#endif
};

class NHttpModule : public Module
{
public:
    NHttpModule() : Module(NHTTP_NAME, NHTTP_HELP, nhttp_params) { }
    ~NHttpModule() { delete params; }
    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;
    unsigned get_gid() const override { return NHttpEnums::NHTTP_GID; }
    const RuleMap* get_rules() const override { return nhttp_events; }
    const NHttpParaList* get_once_params()
    {
        NHttpParaList* ret_val = params;
        params = nullptr;
        return ret_val;
    }

    const PegInfo* get_pegs() const override { return peg_names; }
    PegCount* get_counts() const override { return peg_counts; }
    static void increment_peg_counts(NHttpEnums::PEG_COUNT counter)
        { peg_counts[counter]++; return; }

#ifdef REG_TEST
    static const PegInfo* get_peg_names() { return peg_names; }
    static const PegCount* get_peg_counts() { return peg_counts; }
    static void reset_peg_counts()
    {
        for (unsigned k=0; k < NHttpEnums::PEG_COUNT_MAX; peg_counts[k++] = 0);
    }
#endif

private:
    static const Parameter nhttp_params[];
    static const RuleMap nhttp_events[];
    NHttpParaList* params = nullptr;
    static const PegInfo peg_names[];
    static THREAD_LOCAL PegCount peg_counts[];
};

#endif

