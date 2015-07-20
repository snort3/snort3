//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
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
/*
*   An abstracted interface to the Multi-Pattern Matching routines,
*   thats why we're passing 'void *' objects around.
*
*   Marc A Norton <mnorton@sourcefire.com>
*
*   Updates:
*   3/06 - Added AC_BNFA search
*/

// lowmem_q.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string>

#include "sfksearch.h"
#include "main/snort_debug.h"
#include "main/snort_types.h"
#include "framework/mpse.h"
#include "framework/module.h"
#include "log/messages.h"
#include "time/profiler.h"

using namespace std;

static string s_var;

static const char* s_name = "lowmem_q";
static const char* s_help = "MPSE that minimizes memory used";

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "var", Parameter::PT_STRING, nullptr, nullptr,
      "additional print text" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class LowmemQModule : public Module
{
public:
    LowmemQModule() : Module(s_name, s_help, s_params) { }

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;

public:
    string var;
};

bool LowmemQModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("var") )
        var = v.get_string();

    else
        return false;

    return true;
}

bool LowmemQModule::begin(const char*, int, SnortConfig*)
{
    var.clear();
    return true;
}

//-------------------------------------------------------------------------
// "lowmem_q"
//-------------------------------------------------------------------------

class LowmemQMpse : public Mpse
{
private:
    KTRIE_STRUCT* obj;

public:
    LowmemQMpse(
        bool use_gc,
        void (* user_free)(void*),
        void (* tree_free)(void**),
        void (* list_free)(void**))
        : Mpse(s_name, use_gc)
    {
        obj = KTrieNew(1, user_free, tree_free, list_free);
    }

    ~LowmemQMpse()
    {
        if (obj)
            KTrieDelete(obj);
    }

    int add_pattern(
        SnortConfig*, const uint8_t* P, unsigned m,
        bool noCase, bool negative, void* ID, int) override
    {
        return KTrieAddPattern(obj, P, m, noCase, negative, ID);
    }

    int prep_patterns(
        SnortConfig* sc, MpseBuild build_tree, MpseNegate neg_list) override
    {
        return KTrieCompileWithSnortConf(sc, obj, build_tree, neg_list);
    }

    int _search(
        const unsigned char* T, int n, MpseMatch match,
        void* data, int* current_state) override
    {
        *current_state = 0;
        return KTrieSearchQ(obj, (unsigned char*)T, n, match, data);
    }

    int get_pattern_count() override
    {
        return KTriePatternCount(obj);
    }
};

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new LowmemQModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Mpse* lmq_ctor(
    SnortConfig*,
    class Module* mod,
    bool use_gc,
    void (* user_free)(void*),
    void (* tree_free)(void**),
    void (* list_free)(void**))
{
    LowmemQModule* lmqm = (LowmemQModule*)mod;
    s_var = lmqm->var;
    return new LowmemQMpse(use_gc, user_free, tree_free, list_free);
}

static void lmq_dtor(Mpse* p)
{
    delete p;
}

static void lmq_init()
{
    KTrie_init_xlatcase();
    KTrieInitMemUsed();
}

static void lmq_print()
{
    if ( !KTrieMemUsed() )
        return;

    if ( !s_var.empty() )
        LogMessage("lowmemq.var = %s\n", s_var.c_str());

    double x = (double)KTrieMemUsed();

    LogMessage("[ LowMem Search-Method Memory Used : %g %s ]\n",
        (x > 1.e+6) ?  x/1.e+6 : x/1.e+3,
        (x > 1.e+6) ? "MBytes" : "KBytes");
}

static const MpseApi lmq_api =
{
    {
        PT_SEARCH_ENGINE,
        sizeof(MpseApi),
        SEAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        "Keyword Trie (low memory, moderate performance) MPSE with queued events",
        mod_ctor,
        mod_dtor
    },
    false,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    lmq_ctor,
    lmq_dtor,
    lmq_init,
    lmq_print,
};

const BaseApi* se_lowmem_q = &lmq_api.base;

