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
// mpse.h author Russ Combs <rucombs@cisco.com>

#ifndef MPSE_H
#define MPSE_H

// MPSE = Multi-Pattern Search Engine - ie fast pattern matching The key
// methods of an MPSE are the ability to add patterns, compile a state
// machine from the patterns, and search a buffer for patterns.

#include <string>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "main/snort_types.h"
#include "main/thread.h"
#include "framework/base_api.h"
#include "time/profiler.h"

/*
*   Move these defines to a generic Win32/Unix compatability file,
*   there must be one somewhere...
*/
#ifndef CDECL
#define CDECL
#endif

// this is the current version of the api
#define SEAPI_VERSION ((BASE_API_VERSION << 16) | 0)

struct SnortConfig;
struct MpseApi;

typedef int (* MpseBuild)(SnortConfig*, void* id, void** existing_tree);
typedef int (* MpseNegate)(void* id, void** list);
typedef int (* MpseMatch)(void* id, void* tree, int index, void* data, void* neg_list);

class SO_PUBLIC Mpse
{
public:
    static uint64_t get_pattern_byte_count();
    static void reset_pattern_byte_count();

public:
    virtual ~Mpse() { }

    virtual int add_pattern(
        SnortConfig* sc, const uint8_t* pat, unsigned len,
        bool noCase, bool negate, void* ID, int IID) = 0;

    virtual int prep_patterns(
    SnortConfig*, MpseBuild, MpseNegate) = 0;

    int search(
    const unsigned char* T, int n, MpseMatch,
    void* data, int* current_state);

    virtual int search_all(
    const unsigned char* T, int n, MpseMatch,
    void* data, int* current_state);

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
    const unsigned char* T, int n, MpseMatch,
    void* data, int* current_state) = 0;

private:
    std::string method;
    bool inc_global_counter;
    int verbose;
    const MpseApi* api;
};

#ifdef PERF_PROFILING
extern THREAD_LOCAL ProfileStats mpsePerfStats;
#endif

typedef void (* MpseOptFunc)(SnortConfig*);
typedef void (* MpseExeFunc)();

typedef Mpse* (* MpseNewFunc)(
    SnortConfig* sc,
    class Module*,
    bool use_gc,
    void (* user_free)(void*),
    void (* tree_free)(void**),
    void (* list_free)(void**));

typedef void (* MpseDelFunc)(Mpse*);

struct MpseApi
{
    BaseApi base;
    bool trim;

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

