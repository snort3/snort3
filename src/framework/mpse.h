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
// mpse.h author Russ Combs <rucombs@cisco.com>

#ifndef MPSE_H
#define MPSE_H

// MPSE = Multi-Pattern Search Engine - ie fast pattern matching. The key
// methods of an MPSE are the ability to add patterns, compile a state
// machine from the patterns, and search a buffer for patterns.

#include <string>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "main/snort_types.h"
#include "main/thread.h"
#include "framework/base_api.h"
#include "search_engines/search_common.h"

// this is the current version of the api
#define SEAPI_VERSION ((BASE_API_VERSION << 16) | 0)

struct SnortConfig;
struct MpseApi;
struct ProfileStats;

class SO_PUBLIC Mpse
{
public:
    static uint64_t get_pattern_byte_count();
    static void reset_pattern_byte_count();

public:
    virtual ~Mpse() { }

    struct PatternDescriptor
    {
        bool no_case;
        bool negated;
        bool literal;

        PatternDescriptor(bool noc = false, bool neg = false, bool lit = false)
        { no_case = noc; negated = neg; literal = lit; }
    };

    virtual int add_pattern(
        SnortConfig* sc, const uint8_t* pat, unsigned len,
        const PatternDescriptor&, void* user) = 0;

    virtual int prep_patterns(SnortConfig*) = 0;

    int search(
        const uint8_t* T, int n, MpseMatch, void* context, int* current_state);

    virtual int search_all(
        const uint8_t* T, int n, MpseMatch, void* context, int* current_state);

    virtual void set_opt(int) { }
    virtual int print_info() { return 0; }
    virtual int get_pattern_count() { return 0; }

    const char* get_method() { return method.c_str(); }
    void set_verbose(bool b = true) { verbose = b; }

    void set_api(const MpseApi* p) { api = p; }
    const MpseApi* get_api() { return api; }

protected:
    Mpse(const char* method, bool use_gc);

    virtual int _search(
        const uint8_t* T, int n, MpseMatch, void* context, int* current_state) = 0;

private:
    std::string method;
    bool inc_global_counter;
    int verbose;
    const MpseApi* api;
};

extern THREAD_LOCAL ProfileStats mpsePerfStats;

typedef void (* MpseOptFunc)(SnortConfig*);
typedef void (* MpseExeFunc)();

typedef Mpse* (* MpseNewFunc)(
    SnortConfig* sc, class Module*, bool use_gc, const MpseAgent*);

typedef void (* MpseDelFunc)(Mpse*);

struct MpseApi
{
    BaseApi base;
    bool trim; // set true for NFAs to trim leading \0

    MpseOptFunc activate;
    MpseOptFunc setup;
    MpseExeFunc start;
    MpseExeFunc stop;
    MpseNewFunc ctor;
    MpseDelFunc dtor;
    MpseExeFunc init;
    MpseExeFunc print;
};

#endif

