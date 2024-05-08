//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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
// machine from the patterns, and search either a single buffer or a set
// of (related) buffers for patterns.

// the SEAPI_VERSION will change if anything in this file changes.
// see also framework/base_api.h.

#include <string>

#include "framework/base_api.h"
#include "main/snort_types.h"
#include "search_engines/search_common.h"
//#include "framework/mpse_batch.h"

namespace snort
{
// this is the current version of the api
#define SEAPI_VERSION ((BASE_API_VERSION << 16) | 1)

struct SnortConfig;
struct MpseApi;
struct MpseBatch;

class SO_PUBLIC Mpse
{
public:
    enum MpseType
    {
        MPSE_TYPE_NORMAL = 0,
        MPSE_TYPE_OFFLOAD = 1
    };

    enum MpseRespType
    {
        MPSE_RESP_COMPLETE_FAIL    = -1,
        MPSE_RESP_NOT_COMPLETE     = 0,
        MPSE_RESP_COMPLETE_SUCCESS = 1
    };

    virtual ~Mpse() = default;

    struct PatternDescriptor
    {
        bool no_case;
        bool negated;
        bool literal;
        bool multi_match;

        unsigned flags;

        PatternDescriptor(
            bool noc = false, bool neg = false, bool lit = false, bool multi = false, unsigned f = 0)
        { no_case = noc; negated = neg; literal = lit; multi_match = multi; flags = f; }
    };

    virtual int add_pattern(
        const uint8_t* pat, unsigned len, const PatternDescriptor&, void* user) = 0;

    virtual int prep_patterns(SnortConfig*) = 0;

    virtual void reuse_search() { }

    virtual int search(
        const uint8_t* T, int n, MpseMatch, void* context, int* current_state) = 0;

    virtual int search_all(
        const uint8_t* T, int n, MpseMatch, void* context, int* current_state);

    virtual void search(MpseBatch&, MpseType);

    virtual MpseRespType receive_responses(MpseBatch&, MpseType)
    { return MPSE_RESP_COMPLETE_SUCCESS; }

    static MpseRespType poll_responses(MpseBatch*&, MpseType);

    virtual void set_opt(int) { }
    virtual int print_info() { return 0; }
    virtual int get_pattern_count() const { return 0; }

    virtual bool serialize(uint8_t*&, size_t&) const { return false; }
    virtual bool deserialize(const uint8_t*, size_t) { return false; }
    virtual void get_hash(std::string&) { }

    const char* get_method() { return method.c_str(); }
    void set_verbose(bool b = true) { verbose = b; }

    void set_api(const MpseApi* p) { api = p; }
    const MpseApi* get_api() { return api; }

protected:
    Mpse(const char* method);

private:
    std::string method;
    int verbose = 0;
    const MpseApi* api = nullptr;
};

typedef void (* MpseOptFunc)(SnortConfig*);
typedef void (* MpseExeFunc)();

typedef Mpse* (* MpseNewFunc)(const SnortConfig*, class Module*, const MpseAgent*);
typedef void (* MpseDelFunc)(Mpse*);

typedef Mpse::MpseRespType (* MpsePollFunc)(MpseBatch*&, Mpse::MpseType);

#define MPSE_BASE   0x00  // no optional features
#define MPSE_REGEX  0x02  // supports regex patterns
#define MPSE_ASYNC  0x04  // does asynchronous (lookaside) searches
#define MPSE_MTBLD  0x08  // support multithreaded / parallel compilation

struct MpseApi
{
    BaseApi base;
    uint32_t flags;  // bitmask of MPSE_*

    MpseOptFunc activate;
    MpseOptFunc setup;
    MpseExeFunc start;
    MpseExeFunc stop;
    MpseNewFunc ctor;
    MpseDelFunc dtor;
    MpseExeFunc init;
    MpseExeFunc print;
    MpsePollFunc poll;
};
}
#endif

