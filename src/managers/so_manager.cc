//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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
#include <sstream>

#include "log/messages.h"
#include "framework/decode_data.h"
#include "framework/inspector.h"
#include "framework/module.h"
#include "main/snort_config.h"
#include "parser/parse_so_rule.h"

using namespace snort;
using namespace std;

//-------------------------------------------------------------------------
// plugins
//-------------------------------------------------------------------------
SoRules::~SoRules()
{
    api.clear();
    handles.clear();
}

void SoManager::add_plugin(const SoApi* api, SnortConfig* sc, SoHandlePtr handle)
{
    sc->so_rules->api.emplace_back(api);
    sc->so_rules->handles.emplace_back(handle);
}

void SoManager::dump_plugins()
{
    Dumper d("SO Rules");

    for ( auto* p : SnortConfig::get_conf()->so_rules->api )
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

static const SoApi* get_so_api(const char* soid, SoRules* so_rules)
{
    for ( auto* p : so_rules->api )
        if ( !strcmp(p->base.name, soid) )
            return p;

    return nullptr;
}

const char* SoManager::get_so_rule(const char* soid, SnortConfig* sc)
{
    const SoApi* api = get_so_api(soid, sc->so_rules);

    if ( !api )
        return nullptr;

    const char* rule = revert(api->rule, api->length);

    return rule;
}

SoEvalFunc SoManager::get_so_eval(const char* soid, const char* so, void** data, SnortConfig* sc)
{
    const SoApi* api = get_so_api(soid, sc->so_rules);

    if ( !api || !api->ctor )
        return nullptr;

    return api->ctor(so, data);
}

void SoManager::delete_so_data(const char* soid, void* pv, SoRules* so_rules)
{
    if (!pv or !so_rules)
        return;
    const SoApi* api = get_so_api(soid, so_rules);

    if ( api && api->dtor )
        api->dtor(pv);
}

//-------------------------------------------------------------------------

void SoManager::dump_rule_stubs(const char*, SnortConfig* sc)
{
    unsigned c = 0;

    for ( auto* p : sc->so_rules->api )
    {
        const char* rule = revert(p->rule, p->length);

        if ( !rule )
            continue;

        std::string stub;

        if ( !get_so_stub(rule, stub) )
            continue;

        cout << stub << endl;

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

    std::ios_base::fmtflags f(cout.flags());
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
    cout.flags(f);
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

//-------------------------------------------------------------------------
// so_proxy inspector
//-------------------------------------------------------------------------
static const char* sp_name = "so_proxy";
static const char* sp_help = "a proxy inspector to track flow data from SO rules (internal use only)";
class SoProxy : public Inspector
{
public:
    void eval(Packet*) override { }
    bool configure(SnortConfig* sc) override
    {
        for( auto i : sc->so_rules->handles )
            handles.emplace_back(i);
        sc->so_rules->proxy = this;
        return true;
    }
    ~SoProxy() override { handles.clear(); }

private:
    std::list<SoHandlePtr> handles;
};

static const Parameter sp_params[] =
{
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class SoProxyModule : public Module
{
public:
    SoProxyModule() : Module(sp_name, sp_help, sp_params) { }
    Usage get_usage() const override
    { return GLOBAL; }
};

static Module* mod_ctor()
{ return new SoProxyModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* sp_ctor(Module*)
{
    return new SoProxy;
}

static void sp_dtor(Inspector* p)
{
    delete p;
}

static const InspectApi so_proxy_api
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        sp_name,
        sp_help,
        mod_ctor,
        mod_dtor
    },
    IT_PASSIVE,
    PROTO_BIT__NONE,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit,
    nullptr, // tterm,
    sp_ctor,
    sp_dtor,
    nullptr, // ssn
    nullptr  // reset
};

const BaseApi* so_proxy_plugins[] =
{
    &so_proxy_api.base,
    nullptr
};

void SoManager::load_so_proxy()
{
    PluginManager::load_plugins(so_proxy_plugins);
}
