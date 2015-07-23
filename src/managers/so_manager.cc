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
#include <iomanip>
#include <iostream>
#include <sstream>
using namespace std;

#include "plugin_manager.h"
#include "main/snort_types.h"
#include "main/snort_config.h"
#include "main/snort_debug.h"
#include "framework/so_rule.h"
#include "framework/module.h"
#include "utils/util.h"
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

// FIXIT-L eliminate this arbitrary limit on rule text size
const unsigned max_rule = 128000;
static uint8_t so_buf[max_rule];

static const uint8_t* compress(const string& text, unsigned& len)
{
    const char* s = text.c_str();
    z_stream stream;

    stream.next_in = (Bytef*)s;
    stream.avail_in = text.size();

    stream.next_out = so_buf;
    stream.avail_out = max_rule;

    stream.zalloc = nullptr;
    stream.zfree = nullptr;

    stream.total_in = 0;
    stream.total_out = 0;

    len = 0;

    if ( deflateInit(&stream, Z_DEFAULT_COMPRESSION) != Z_OK )
        return nullptr;

    if ( deflate(&stream, Z_FINISH) == Z_STREAM_END )
        len= stream.total_out;

    deflateEnd(&stream);
    return so_buf;
}

// FIXIT-L make this into a general utility for one shot decompress
// and add class for stream decompress
static const char* expand(const uint8_t* data, unsigned len)
{
    z_stream stream;

    stream.next_in = (Bytef*)data;
    stream.avail_in = (uInt)len;

    stream.next_out = (Bytef*)so_buf;
    stream.avail_out = (uInt)(max_rule - 1);

    stream.zalloc = nullptr;
    stream.zfree = nullptr;

    stream.total_in = 0;
    stream.total_out = 0;

    if ( inflateInit(&stream) != Z_OK )
        return nullptr;

    if ( inflate(&stream, Z_SYNC_FLUSH) != Z_STREAM_END )
        return nullptr;

    assert(stream.total_out < max_rule);
    so_buf[stream.total_out] = '\0';

    return (char*)so_buf;
}

//-------------------------------------------------------------------------

static void strvrt(const string& text, string& data)
{
    unsigned len = 0;
    const uint8_t* d = compress(text, len);

    // lose the zlib header
    assert(len > 2 && d[0] == 0x78 && d[1] == 0x9C);
    d += 2;
    len -= 2;

    data.assign((char*)d, len);

    // generate xor key
    // FIXIT-L there is no hard core crypto requirement here
    // but rand() is known to be weak, especially in the lower bits
    // nonetheless this seems to work as good as the basic
    // C++ 11 default generator and uniform distribution
    uint8_t key = (uint8_t)(rand() >> 16);
    if ( !key )
        key = 0xA5;

    for ( unsigned i = 0; i < len; i++ )
        data[i] ^= key;

    data.append(1, (char)key);
}

static const char* revert(const uint8_t* data, unsigned len)
{
    if ( !len )
        return (char*)data;

    uint8_t key = data[--len];
    string s((char*)data, len);

    for ( unsigned i = 0; i < len-1; i++ )
        s[i] ^= key;

    // force the zlib header
    s.insert(0, "\x78\x9C");

    return expand((uint8_t*)s.c_str(), s.size());
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

    if ( !api->length )
        return nullptr;

    const char* rule = revert(api->rule, api->length);

    if ( !rule )
        return nullptr;

    // FIXIT-L this approach won't tolerate spaces and might get
    // fooled by matching content (should it precede this)
    char opt[32];
    snprintf(opt, sizeof(opt), "soid:%s;", soid);
    const char* s = strstr(rule, opt);

    return s ? s + strlen(opt) : nullptr;
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

void SoManager::dump_rule_stubs(const char*)
{
    unsigned c = 0;

    for ( auto* p : s_rules )
    {
        const char* s;
        const char* rule = revert(p->rule, p->length);

        if ( !rule )
            continue;

        // FIXIT-L need to properly parse rule to avoid
        // confusing other text for soid option
        if ( !(s = strstr(rule, "soid:")) )
            continue;

        if ( !(s = strchr(s, ';')) )
            continue;

        // FIXIT-L strip newlines (optional?)
        if ( !p->length )
            cout << rule << endl;
        else
        {
            string stub(rule, ++s-rule);
            cout << stub << ")" << endl;
        }
        ++c;
    }
    if ( !c )
        cerr << "no rules to dump" << endl;
}

static void get_var(const string& s, string& v)
{
    v.clear();
    size_t pos = s.find("soid");

    if ( pos == string::npos )
        return;

    pos = s.find("|", pos+1);

    if ( pos == string::npos )
        return;

    size_t end = s.find(";", ++pos);

    if ( end == string::npos )
        return;

    v = s.substr(pos, end-pos);
}

void SoManager::rule_to_hex(const char*)
{
    stringstream buffer;
    buffer << cin.rdbuf();
    string text = buffer.str();

    unsigned idx;
    string data;
    strvrt(text, data);

    string var;
    get_var(text, var);

    cout << "const uint8_t rule_" << var;
    cout << "[] =" << endl;
    cout << "{" << endl;
    cout << hex << uppercase;

    for ( idx = 0; idx < data.size(); idx++ )
    {
        if ( idx && !(idx % 12) )
            cout << endl;

        uint8_t u = data[idx];
        cout << "0x" << setfill('0') << setw(2) << hex << (int)u << ", ";
    }
    if ( idx % 16 )
        cout << endl;

    cout << dec;
    cout << "};" << endl;
    cout << "const unsigned rule_" << var << "_len = ";
    cout << data.size() << ";" << endl;
}

void SoManager::rule_to_text(const char*)
{
    stringstream buffer;
    buffer << cin.rdbuf();
    string text = buffer.str();

    unsigned len = text.size(), idx;
    const uint8_t* data = (uint8_t*)text.c_str();

    string var;
    get_var(text, var);

    cout << "const uint8_t rule_" << var;
    cout << "[] =" << endl;
    cout << "{" << endl;
    cout << hex << uppercase;

    for ( idx = 0; idx < len; idx++ )
    {
        if ( idx && !(idx % 12) )
            cout << endl;
        cout << "0x" << setfill('0') << setw(2) << (unsigned)data[idx] << ", ";
    }
    if ( idx % 16 )
        cout << endl;

    cout << dec;
    cout << "};" << endl;
    cout << "const unsigned rule_" << var;
    cout << "_len = 0;" << endl;
}

