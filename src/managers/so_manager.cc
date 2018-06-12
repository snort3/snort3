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
// so_manager.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "so_manager.h"

#include <zlib.h>

#include <cassert>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <list>
#include <sstream>

#include "log/messages.h"

using namespace std;

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
    snort::Dumper d("SO Rules");

    for ( auto* p : s_rules )
        d.dump(p->base.name, p->base.version);
}

//-------------------------------------------------------------------------
// so rules
//-------------------------------------------------------------------------

// FIXIT-L eliminate this arbitrary limit on rule text size
const int window_bits = -9;
const unsigned max_rule = 128000;
static uint8_t so_buf[max_rule];

static const uint8_t* compress(const string& text, unsigned& len)
{
    len = 0;
    const char* s = text.c_str();
    z_stream stream;

    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;
    stream.next_in = Z_NULL;

    // v2 avoids the header and trailer
    int ret = deflateInit2(
        &stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, window_bits, 1, Z_DEFAULT_STRATEGY);

    if ( ret != Z_OK )
        return nullptr;

    stream.next_in = const_cast<Bytef*>(reinterpret_cast<const uint8_t*>(s));
    stream.avail_in = text.size();

    stream.next_out = so_buf;
    stream.avail_out = max_rule;

    ret = deflate(&stream, Z_FINISH);
    (void)deflateEnd(&stream);

    if ( ret != Z_STREAM_END )
        return nullptr;

    len= stream.total_out;
    assert(stream.avail_out > 0);

    return so_buf;
}

// FIXIT-L make this into a general utility for one shot decompress
// and add class for stream decompress
static const char* expand(const uint8_t* data, unsigned len)
{
    z_stream stream;

    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;
    stream.next_in = Z_NULL;
    stream.avail_in = 0;

    if ( inflateInit2(&stream, window_bits) != Z_OK )
        return nullptr;

    stream.next_in = const_cast<Bytef*>(data);
    stream.avail_in = (uInt)len;

    stream.next_out = (Bytef*)so_buf;
    stream.avail_out = (uInt)(max_rule - 1);

    int ret = inflate(&stream, Z_FINISH);
    (void)inflateEnd(&stream);

    if ( ret != Z_STREAM_END )
        return nullptr;

    // sanity check
    if ( stream.avail_in or !stream.avail_out )
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

    data.assign((const char*)d, len);

    // generate xor key.  there is no hard core crypto requirement here but
    // rand() is known to be weak, especially in the lower bits nonetheless
    // this seems to work as good as the basic C++ 11 default generator and
    // uniform distribution

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
        return (const char*)data;

    uint8_t key = data[--len];
    string s((const char*)data, len);

    for ( unsigned i = 0; i < len; i++ )
        s[i] ^= key;

    return expand((const uint8_t*)s.c_str(), s.size());
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
        return ")";  // plain stub is full rule

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

        if ( *rule == '\n' )
            ++rule;

        unsigned n = p->length ? s-rule+1 : strlen(rule);

        if ( n and rule[n-1] == '\n' )
            --n;

        cout.write(rule, n);

        if ( p->length )
            cout << " )";

        cout << endl;

        ++c;
    }
    if ( !c )
        cerr << "no rules to dump" << endl;
}

static void strip_newline(string& s)
{
    if ( s.find_last_of('\n') == s.length()-1 )
        s.pop_back();
}

static void get_var(const string& s, string& v)
{
    v.clear();
    size_t pos = s.find("soid:");

    if ( pos == string::npos )
        return;

    pos += 5;

    size_t end = s.find(';', pos);

    if ( end == string::npos )
        return;

    v = s.substr(pos, end-pos);
}

void SoManager::rule_to_hex(const char*)
{
    stringstream buffer;
    buffer << cin.rdbuf();

    string text = buffer.str();
    strip_newline(text);

    unsigned idx;
    string data;
    strvrt(text, data);

    string var;
    get_var(text, var);

    const unsigned hex_per_row = 16;

    cout << "static const uint8_t rule_" << var;
    cout << "[] =" << endl;
    cout << "{" << endl << "   ";
    cout << hex << uppercase;

    for ( idx = 0; idx < data.size(); idx++ )
    {
        if ( idx && !(idx % hex_per_row) )
            cout << endl << "   ";

        uint8_t u = data[idx];
        cout << " 0x" << setfill('0') << setw(2) << hex << (int)u << ",";
    }
    if ( idx % hex_per_row )
        cout << endl;

    cout << dec;
    cout << "};" << endl;
    cout << "static const unsigned rule_" << var << "_len = ";
    cout << data.size() << ";" << endl;
}

void SoManager::rule_to_text(const char* delim)
{
    stringstream buffer;
    buffer << cin.rdbuf();

    string text = buffer.str();
    strip_newline(text);

    string var;
    get_var(text, var);

    if ( !delim or !*delim )
        delim = "[Snort_SO_Rule]";

    cout << "static const char* rule_" << var << " = ";
    cout << "R\"" << delim << "(" << endl;
    cout << text << endl;
    cout << ')' << delim << "\";" << endl;
    cout << endl;
    cout << "static const unsigned rule_" << var << "_len = 0;" << endl;
}

