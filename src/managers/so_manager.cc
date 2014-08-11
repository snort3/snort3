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
// so_manager.cc author Russ Combs <rucombs@cisco.com>

#include "so_manager.h"

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
#include "framework/so_rule.h"
#include "framework/module.h"
#include "snort.h"
#include "snort_debug.h"
#include "util.h"
#include "parser/parser.h"
#include "log/messages.h"

static list<const SoApi*> s_rules;

//-------------------------------------------------------------------------
// plugins
//-------------------------------------------------------------------------

void SoManager::add_plugin(const SoApi* api)
{
    s_rules.push_back(api);
}

void SoManager::release_plugins()
{
    s_rules.clear();
}

void SoManager::dump_plugins()
{
    Dumper d("SO Rules");

    for ( auto* p : s_rules )
        d.dump(p->base.name, p->base.version);
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

const char* SoManager::get_so_options(const char* soid)
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

    return s ? s + strlen(opt) + 1 : nullptr;
}

SoEvalFunc SoManager::get_so_eval(const char* soid, const char* so, void** data)
{
    const SoApi* api = get_so_api(soid);

    if ( !api || !api->ctor )
        return nullptr;

    return api->ctor(so, data);
}

void SoManager::delete_so_data(const char* soid, void* pv)
{
    const SoApi* api = get_so_api(soid);

    if ( api && api->dtor )
        api->dtor(pv);
}

//-------------------------------------------------------------------------

void SoManager::dump_rule_stubs(const char* path)
{
    unsigned c = 0;
    std::ofstream ofs(path);

    for ( auto* p : s_rules )
    {
        const char* s;
        const char* rule = uncompress(p->rule, p->length);

        if ( !rule )
            continue;

        // FIXIT need to properly parse rule to avoid
        // confusing other text for soid option
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

