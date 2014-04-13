/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
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
*/
// ips_manager.cc author Russ Combs <rucombs@cisco.com>

#include "ips_manager.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>

#include <list>
#include <fstream>
using namespace std;

#include "snort_types.h"
#include "plugin_manager.h"
#include "framework/ips_option.h"
#include "framework/so_rule.h"
#include "ips_options/ips_options.h"
#include "snort.h"
#include "snort_debug.h"
#include "util.h"
#include "parser/parser.h"
#include "log/messages.h"

struct Option
{
    const IpsApi* api;
    bool init;

    Option(const IpsApi* p)
    { api = p; init = false; };
};

typedef list<Option*> OptionList;
static OptionList s_options;
static list<const SoApi*> s_rules;

static const char* current_keyword = nullptr;

//-------------------------------------------------------------------------
// plugins
//-------------------------------------------------------------------------

void IpsManager::add_plugin(const IpsApi* api)
{
    s_options.push_back(new Option(api));
}

void IpsManager::add_plugin(const SoApi* api)
{
    s_rules.push_back(api);
}

void IpsManager::release_plugins()
{
    for ( auto* p : s_options )
        delete p;

    s_options.clear();
    s_rules.clear();
}

void IpsManager::dump_plugins()
{
    {
        Dumper d("IPS Options");

        for ( auto* p : s_options )
            d.dump(p->api->base.name, p->api->base.version);
    }
    Dumper d("SO Rules");

    for ( auto* p : s_rules )
        d.dump(p->base.name, p->base.version);
}

//-------------------------------------------------------------------------
// ips options
//-------------------------------------------------------------------------

void IpsManager::delete_option(IpsOption* ips)
{
    const IpsApi* api = (const IpsApi*)
        PluginManager::get_api(PT_IPS_OPTION, ips->get_name());

    if ( api )
        api->dtor(ips);
}

//-------------------------------------------------------------------------

static Option* get_opt(const char *keyword)
{
    for ( auto* p : s_options )
        if ( !strcasecmp(p->api->base.name, keyword) )
            return p;

    return nullptr;
}

const char* IpsManager::get_option_keyword()
{
    return current_keyword;
}

bool IpsManager::get_option(
    SnortConfig* sc, OptTreeNode* otn, int proto,
    const char* keyword, char* args, int& type)
{
    Option* opt = get_opt(keyword);

    if ( !opt )
        return false;

#ifdef NDEBUG
    UNUSED(proto);
#else
    assert(proto == otn->proto);
#endif

    if ( !opt->init )
    {
        if ( opt->api->ginit )
            opt->api->ginit(sc);
        opt->init = true;
    }
    // FIXIT verify api->protos and api->max_per_rule
    // before calling ctor
    current_keyword = keyword;
    IpsOption* ips = opt->api->ctor(sc, args, otn);
    current_keyword = nullptr;

    if ( !ips )
        return false;

    void* dup;

    if ( !add_detection_option(
        sc, ips->get_type(), ips, &dup) )
    {
        delete ips;
        ips = (IpsOption*)dup;
    }

    OptFpList* fpl = AddOptFuncToList(ips_option_eval, otn);
    fpl->context = ips;
    fpl->type = ips->get_type();

    if ( ips->is_relative() )
        fpl->isRelative = 1;

    otn_set_plugin(otn, ips->get_type());
    type = opt->api->type;
    return true;
}

//-------------------------------------------------------------------------

void IpsManager::global_init(SnortConfig*)
{
}

void IpsManager::global_term(SnortConfig* sc)
{
    for ( auto* p : s_options )
        if ( p->init && p->api->gterm )
        {
            p->api->gterm(sc);
            p->init = false;
        }
}

void IpsManager::setup_options()
{
    for ( auto* p : s_options )
        if ( p->init && p->api->tinit )
            p->api->tinit(snort_conf);
}

void IpsManager::clear_options()
{
    for ( auto* p : s_options )
        if ( p->init && p->api->tterm )
            p->api->tterm(snort_conf);
}

bool IpsManager::verify()
{
    for ( auto* p : s_options )
        if ( p->init && p->api->verify )
            if ( !p->api->verify() )
                return false;

    return true;
}

//-------------------------------------------------------------------------
// so rules
//-------------------------------------------------------------------------

#define GZIP_WBITS 31

// FIXIT make this into a general utility for one shot decompress
// and add class for stream decompress
const char*  uncompress(const uint8_t* data, unsigned len)
{
    const unsigned max_rule = 65536;
    static char buf[max_rule];

    z_stream stream;

    stream.next_in = (Bytef*)data;
    stream.avail_in = (uInt)len;

    stream.next_out = (Bytef*)buf;
    stream.avail_out = (uInt)(max_rule - 1);

    stream.zalloc = nullptr;
    stream.zfree = nullptr;

    stream.total_in = 0;
    stream.total_out = 0;
 
    if ( inflateInit2(&stream, GZIP_WBITS) != Z_OK )
        return nullptr;

    if ( inflate(&stream, Z_SYNC_FLUSH) != Z_STREAM_END )
        return nullptr;

    assert(stream.total_out < max_rule);
    buf[stream.total_out] = '\0';

    return buf;
}

//-------------------------------------------------------------------------

static const SoApi* get_so_api(const char* soid)
{
    for ( auto* p : s_rules )
        if ( !strcmp(p->base.name, soid) )
            return p;

    return nullptr;
}

const char* IpsManager::get_so_options(const char* soid)
{
    const SoApi* api = get_so_api(soid);

    if ( !api )
        return nullptr;

    const char* rule = uncompress(api->rule, api->length);

    if ( !rule )
        return nullptr;

    // FIXIT this approach won't tolerate spaces and might get
    // fooled by matching content (should it precede this)
    char opt[32];
    snprintf(opt, sizeof(opt), "; soid:%s", soid);
    const char* s = strstr(rule, opt);

    return s ? s + strlen(opt) : nullptr;
}

so_eval_f IpsManager::get_so_eval(const char* soid, const char* so, void** data)
{
    const SoApi* api = get_so_api(soid);

    if ( !api || !api->ctor )
        return nullptr;

    return api->ctor(so, data);
}

void IpsManager::delete_so_data(const char* soid, void* pv)
{
    const SoApi* api = get_so_api(soid);

    if ( api && api->dtor )
        api->dtor(pv);
}

//-------------------------------------------------------------------------

void IpsManager::dump_rule_stubs(const char* path)
{
    unsigned c = 0;
    std::ofstream ofs(path);

    for ( auto* p : s_rules )
    {
        const char* s;
        const char* rule = uncompress(p->rule, p->length);

        if ( !rule )
            continue;

        if ( !(s = strstr(rule, "soid:")) )
            continue;

        if ( !(s = strchr(s, ';')) )
            continue;

        string stub(rule, ++s-rule);
        ofs << stub << ")" << endl;
        ++c;
    }
    LogMessage("%u rule stubs dumped.\n", c);
}

