//--------------------------------------------------------------------------
// Copyright (C) 2026 Cisco and/or its affiliates. All rights reserved.
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
// socks_ips.cc author Raza Shafiq <rshafiq@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "socks_ips.h"

#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hash_key_operations.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "socks_flow_data.h"

#include <algorithm>
#include <cctype>

using namespace snort;

#define s_name "socks_version"
#define s_help "match SOCKS version (4 or 5)"

//-------------------------------------------------------------------------
// socks_version - Match SOCKS protocol version
//-------------------------------------------------------------------------

static THREAD_LOCAL ProfileStats socks_version_prof;

class SocksVersionOption : public IpsOption
{
public:
    SocksVersionOption(uint8_t v) : IpsOption(s_name), version(v) { }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;
    EvalStatus eval(Cursor&, Packet*) override;

private:
    uint8_t version;
};

uint32_t SocksVersionOption::hash() const
{
    uint32_t a = version, b = IpsOption::hash(), c = 0;
    mix(a, b, c);
    finalize(a, b, c);
    return c;
}

bool SocksVersionOption::operator==(const IpsOption& ips) const
{
    if ( !IpsOption::operator==(ips) )
        return false;

    const auto& rhs = static_cast<const SocksVersionOption&>(ips);
    return version == rhs.version;
}

IpsOption::EvalStatus SocksVersionOption::eval(Cursor&, Packet* p)
{
    // cppcheck-suppress unreadVariable
    RuleProfile profile(socks_version_prof);

    if ( !p->flow )
        return NO_MATCH;

    const auto* fd = static_cast<const SocksFlowData*>(p->flow->get_flow_data(SocksFlowData::get_inspector_id()));
    if ( !fd )
        return NO_MATCH;

    uint8_t flow_version = fd->get_socks_version();
    if ( version == flow_version )
        return MATCH;

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// socks_version module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~version", Parameter::PT_INT, "4:5", nullptr,
      "SOCKS version to match (4 or 5)" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class SocksVersionModule : public Module
{
public:
    SocksVersionModule() : Module(s_name, s_help, s_params) { }

    bool set(const char*, Value& v, SnortConfig*) override
    {
        assert(v.is("~version"));
        version = v.get_uint8();
        return true;
    }

    ProfileStats* get_profile() const override
    { return &socks_version_prof; }

    Usage get_usage() const override
    { return DETECT; }

public:
    uint8_t version = SOCKS5_VERSION;
};

//-------------------------------------------------------------------------
// socks_version api
//-------------------------------------------------------------------------

static Module* socks_version_mod_ctor()
{ return new SocksVersionModule; }

static void socks_version_mod_dtor(Module* m)
{ delete m; }

// cppcheck-suppress constParameterCallback
static IpsOption* socks_version_ctor(Module* p, IpsInfo&)
{
    const auto* m = static_cast<const SocksVersionModule*>(p);
    return new SocksVersionOption(m->version);
}

static void socks_version_dtor(IpsOption* p) 
{ delete p; }

static const IpsApi socks_version_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        socks_version_mod_ctor,
        socks_version_mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    socks_version_ctor,
    socks_version_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// socks_state - Match SOCKS state (init/auth/request_response/established/error)
//-------------------------------------------------------------------------

#undef s_name
#undef s_help
#define s_name "socks_state"
#define s_help "match SOCKS state (1=auth, 2=request_response, 3=established, 4=error)"

static THREAD_LOCAL ProfileStats socks_state_prof;

enum SocksStateClass : uint8_t
{
    SOCKS_STATE_CLASS_INIT = 0,
    SOCKS_STATE_CLASS_AUTH,
    SOCKS_STATE_CLASS_REQUEST_RESPONSE,
    SOCKS_STATE_CLASS_ESTABLISHED,
    SOCKS_STATE_CLASS_ERROR
};

static uint8_t get_socks_state_class(SocksState state)
{
    switch ( state )
    {
    case SOCKS_STATE_INIT:
        return SOCKS_STATE_CLASS_INIT;

    case SOCKS_STATE_V5_AUTH_NEGOTIATION:
    case SOCKS_STATE_V5_AUTH_REQUEST:
    case SOCKS_STATE_V5_AUTH_RESPONSE:
    case SOCKS_STATE_V5_USERNAME_PASSWORD_AUTH:
    case SOCKS_STATE_V5_BIND_REVERSE_AUTH_NEGOTIATION:
    case SOCKS_STATE_V5_BIND_REVERSE_AUTH_RESPONSE:
        return SOCKS_STATE_CLASS_AUTH;

    case SOCKS_STATE_V4_CONNECT_REQUEST:
    case SOCKS_STATE_V4_CONNECT_RESPONSE:
    case SOCKS_STATE_V4_BIND_SECOND_RESPONSE:
    case SOCKS_STATE_V5_CONNECT_REQUEST:
    case SOCKS_STATE_V5_CONNECT_RESPONSE:
    case SOCKS_STATE_V5_BIND_REVERSE_CONNECT_REQUEST:
    case SOCKS_STATE_V5_BIND_REVERSE_CONNECT_RESPONSE:
        return SOCKS_STATE_CLASS_REQUEST_RESPONSE;

    case SOCKS_STATE_ESTABLISHED:
        return SOCKS_STATE_CLASS_ESTABLISHED;

    case SOCKS_STATE_ERROR:
        return SOCKS_STATE_CLASS_ERROR;
    }

    return SOCKS_STATE_CLASS_ERROR;
}

static bool parse_socks_state_class(const char* s, uint8_t& out)
{
    if ( !s || !*s )
        return false;

    bool ok = false;
    uint64_t value = Parameter::get_uint(s, ok);
    if ( ok )
    {
        if ( value >= SOCKS_STATE_CLASS_AUTH && value <= SOCKS_STATE_CLASS_ERROR )
        {
            out = static_cast<uint8_t>(value);
            return true;
        }
        return false;
    }

    std::string key(s);
    std::transform(key.begin(), key.end(), key.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    std::replace(key.begin(), key.end(), '-', '_');

    if ( key == "auth" )
        out = SOCKS_STATE_CLASS_AUTH;
    else if ( key == "request_response" )
        out = SOCKS_STATE_CLASS_REQUEST_RESPONSE;
    else if ( key == "established" )
        out = SOCKS_STATE_CLASS_ESTABLISHED;
    else if ( key == "error" )
        out = SOCKS_STATE_CLASS_ERROR;
    else
        return false;

    return true;
}

class SocksStateOption : public IpsOption
{
public:
    SocksStateOption(uint8_t s) : IpsOption(s_name), state_class(s) { }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;
    EvalStatus eval(Cursor&, Packet*) override;

private:
    uint8_t state_class;
};

uint32_t SocksStateOption::hash() const
{
    uint32_t a = state_class, b = IpsOption::hash(), c = 0;
    mix(a, b, c);
    finalize(a, b, c);
    return c;
}

bool SocksStateOption::operator==(const IpsOption& ips) const
{
    if ( !IpsOption::operator==(ips) )
        return false;

    const auto& rhs = static_cast<const SocksStateOption&>(ips);
    return state_class == rhs.state_class;
}

IpsOption::EvalStatus SocksStateOption::eval(Cursor&, Packet* p)
{
    // cppcheck-suppress unreadVariable
    RuleProfile profile(socks_state_prof);

    if ( !p->flow )
        return NO_MATCH;

    const auto* fd = static_cast<const SocksFlowData*>(p->flow->get_flow_data(SocksFlowData::get_inspector_id()));
    if ( !fd )
        return NO_MATCH;

    uint8_t flow_class = get_socks_state_class(fd->get_state());
    if ( flow_class == state_class )
        return MATCH;

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// socks_state module
//-------------------------------------------------------------------------

static const Parameter socks_state_params[] =
{
    { "~state", Parameter::PT_STRING, nullptr, nullptr,
      "state to match (1-4 or auth|request_response|established|error)" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class SocksStateModule : public Module
{
public:
    SocksStateModule() : Module(s_name, s_help, socks_state_params) { }

    bool set(const char*, Value& v, SnortConfig*) override
    {
        assert(v.is("~state"));
        uint8_t parsed = 0;
        if ( !parse_socks_state_class(v.get_string(), parsed) )
            return false;
        state_class = parsed;
        return true;
    }

    ProfileStats* get_profile() const override
    { return &socks_state_prof; }

    Usage get_usage() const override
    { return DETECT; }

public:
    uint8_t state_class = SOCKS_STATE_CLASS_ESTABLISHED;
};

//-------------------------------------------------------------------------
// socks_state api
//-------------------------------------------------------------------------

static Module* socks_state_mod_ctor()
{ return new SocksStateModule; }

static void socks_state_mod_dtor(Module* m)
{ delete m; }

// cppcheck-suppress constParameterCallback
static IpsOption* socks_state_ctor(Module* p, IpsInfo&)
{
    const auto* m = static_cast<const SocksStateModule*>(p);
    return new SocksStateOption(m->state_class);
}

static void socks_state_dtor(IpsOption* p)
{ delete p; }

static const IpsApi socks_state_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        socks_state_mod_ctor,
        socks_state_mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    socks_state_ctor,
    socks_state_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// socks_command - Match SOCKS command
//-------------------------------------------------------------------------

#undef s_name
#undef s_help
#define s_name "socks_command"
#define s_help "match SOCKS command (1=CONNECT, 2=BIND, 3=UDP_ASSOCIATE)"

static THREAD_LOCAL ProfileStats socks_command_prof;

class SocksCommandOption : public IpsOption
{
public:
    SocksCommandOption(uint8_t c) : IpsOption(s_name), command(c) { }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;
    EvalStatus eval(Cursor&, Packet*) override;

private:
    uint8_t command;
};

uint32_t SocksCommandOption::hash() const
{
    uint32_t a = command, b = IpsOption::hash(), c = 0;
    mix(a, b, c);
    finalize(a, b, c);
    return c;
}

bool SocksCommandOption::operator==(const IpsOption& ips) const
{
    if ( !IpsOption::operator==(ips) )
        return false;

    const auto& rhs = static_cast<const SocksCommandOption&>(ips);
    return command == rhs.command;
}

IpsOption::EvalStatus SocksCommandOption::eval(Cursor&, Packet* p)
{
    // cppcheck-suppress unreadVariable
    RuleProfile profile(socks_command_prof);

    if ( !p->flow )
        return NO_MATCH;

    const auto* fd = static_cast<const SocksFlowData*>(p->flow->get_flow_data(SocksFlowData::get_inspector_id()));
    if ( !fd )
        return NO_MATCH;

    // Only evaluate if target address has been set (SOCKS request parsed)
    if ( fd->get_target_address().empty() )
        return NO_MATCH;

    if ( fd->get_command() == static_cast<SocksCommand>(command) )
        return MATCH;

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// socks_command module
//-------------------------------------------------------------------------

static const Parameter socks_command_params[] =
{
    { "~command", Parameter::PT_INT, "1:3", nullptr,
      "SOCKS command (1=CONNECT, 2=BIND, 3=UDP_ASSOCIATE)" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class SocksCommandModule : public Module
{
public:
    SocksCommandModule() : Module(s_name, s_help, socks_command_params) { }

    bool set(const char*, Value& v, SnortConfig*) override
    {
        assert(v.is("~command"));
        command = v.get_uint8();
        return true;
    }

    ProfileStats* get_profile() const override
    { return &socks_command_prof; }

    Usage get_usage() const override
    { return DETECT; }

public:
    uint8_t command = SOCKS_CMD_CONNECT;
};

//-------------------------------------------------------------------------
// socks_command api
//-------------------------------------------------------------------------

static Module* socks_command_mod_ctor() 
{ return new SocksCommandModule; }

static void socks_command_mod_dtor(Module* m) 
{ delete m; }

// cppcheck-suppress constParameterCallback
static IpsOption* socks_command_ctor(Module* p, IpsInfo&)
{
    const auto* m = static_cast<const SocksCommandModule*>(p);
    return new SocksCommandOption(m->command);
}

static void socks_command_dtor(IpsOption* p)
{ delete p; }

static const IpsApi socks_command_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        socks_command_mod_ctor,
        socks_command_mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    socks_command_ctor,
    socks_command_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// socks_address_type - Match SOCKS address type (SOCKS5-specific)
//-------------------------------------------------------------------------

#undef s_name
#undef s_help
#define s_name "socks_address_type"
#define s_help "match SOCKS address type (1=IPv4, 3=Domain, 4=IPv6) - SOCKS5 only"

static THREAD_LOCAL ProfileStats socks5_address_type_prof;

class Socks5AddressTypeOption : public IpsOption
{
public:
    Socks5AddressTypeOption(uint8_t t) : IpsOption(s_name), addr_type(t) { }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;
    EvalStatus eval(Cursor&, Packet*) override;

private:
    uint8_t addr_type;
};

uint32_t Socks5AddressTypeOption::hash() const
{
    uint32_t a = addr_type, b = IpsOption::hash(), c = 0;
    mix(a, b, c);
    finalize(a, b, c);
    return c;
}

bool Socks5AddressTypeOption::operator==(const IpsOption& ips) const
{
    if ( !IpsOption::operator==(ips) )
        return false;

    const auto& rhs = static_cast<const Socks5AddressTypeOption&>(ips);
    return addr_type == rhs.addr_type;
}

IpsOption::EvalStatus Socks5AddressTypeOption::eval(Cursor&, Packet* p)
{
    // cppcheck-suppress unreadVariable
    RuleProfile profile(socks5_address_type_prof);

    if ( !p->flow )
        return NO_MATCH;

    const auto* fd = static_cast<const SocksFlowData*>(p->flow->get_flow_data(SocksFlowData::get_inspector_id()));
    if ( !fd )
        return NO_MATCH;

    // Only evaluate if target address has been set (SOCKS request parsed)
    if ( fd->get_target_address().empty() )
        return NO_MATCH;

    if ( fd->get_address_type() == static_cast<SocksAddressType>(addr_type) )
        return MATCH;

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// socks5_address_type module
//-------------------------------------------------------------------------

static const Parameter socks5_address_type_params[] =
{
    { "~type", Parameter::PT_INT, "1:4", nullptr,
      "address type (1=IPv4, 3=Domain, 4=IPv6)" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class Socks5AddressTypeModule : public Module
{
public:
    Socks5AddressTypeModule() : Module(s_name, s_help, socks5_address_type_params) { }

    bool set(const char*, Value& v, SnortConfig*) override
    {
        assert(v.is("~type"));
        addr_type = v.get_uint8();
        return true;
    }

    ProfileStats* get_profile() const override
    { return &socks5_address_type_prof; }

    Usage get_usage() const override
    { return DETECT; }

public:
    uint8_t addr_type = SOCKS_ATYP_IPV4;
};

//-------------------------------------------------------------------------
// socks5_address_type api
//-------------------------------------------------------------------------

static Module* socks5_address_type_mod_ctor()
{ return new Socks5AddressTypeModule; }

static void socks5_address_type_mod_dtor(Module* m)
{ delete m; }

// cppcheck-suppress constParameterCallback
static IpsOption* socks5_address_type_ctor(Module* p, IpsInfo&)
{
    const auto* m = static_cast<const Socks5AddressTypeModule*>(p);
    return new Socks5AddressTypeOption(m->addr_type);
}

static void socks5_address_type_dtor(IpsOption* p) 
{ delete p; }

static const IpsApi socks5_address_type_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        socks5_address_type_mod_ctor,
        socks5_address_type_mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP | PROTO_BIT__UDP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    socks5_address_type_ctor,
    socks5_address_type_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// socks_remote_address - Buffer option for destination address
//-------------------------------------------------------------------------

#undef s_name
#undef s_help
#define s_name "socks_remote_address"
#define s_help "set cursor to remote destination address (IP or domain)"

static THREAD_LOCAL ProfileStats socks_remote_address_prof;

class SocksRemoteAddressOption : public IpsOption
{
public:
    SocksRemoteAddressOption(const std::string& addr = "") : IpsOption(s_name), match_addr(addr) { }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;
    EvalStatus eval(Cursor&, Packet*) override;
    CursorActionType get_cursor_type() const override
    { return match_addr.empty() ? CAT_SET_FAST_PATTERN : CAT_NONE; }

private:
    std::string match_addr;
};

uint32_t SocksRemoteAddressOption::hash() const
{
    uint32_t a = IpsOption::hash(), b = 0, c = 0;
    mix_str(a, b, c, match_addr.c_str());
    finalize(a, b, c);
    return c;
}

bool SocksRemoteAddressOption::operator==(const IpsOption& ips) const
{
    if ( !IpsOption::operator==(ips) )
        return false;
    const SocksRemoteAddressOption& rhs = static_cast<const SocksRemoteAddressOption&>(ips);
    return match_addr == rhs.match_addr;
}

IpsOption::EvalStatus SocksRemoteAddressOption::eval(Cursor& c, Packet* p)
{
    // cppcheck-suppress unreadVariable
    RuleProfile profile(socks_remote_address_prof);

    if ( !p->flow )
        return NO_MATCH;

    const auto* fd = static_cast<const SocksFlowData*>(p->flow->get_flow_data(SocksFlowData::get_inspector_id()));
    if ( !fd )
        return NO_MATCH;

    const std::string& addr = fd->get_target_address();
    if ( addr.empty() )
        return NO_MATCH;

    // If match_addr is set, do direct string comparison
    if ( !match_addr.empty() )
        return (addr.find(match_addr) != std::string::npos) ? MATCH : NO_MATCH;

    // Otherwise, set cursor for content matching
    c.set(s_name, reinterpret_cast<const uint8_t*>(addr.data()), addr.length());
    return MATCH;
}

//-------------------------------------------------------------------------
// socks_remote_address module
//-------------------------------------------------------------------------

static const Parameter socks_remote_address_params[] =
{
    { "~", Parameter::PT_STRING, nullptr, nullptr, "address to match (substring)" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class SocksRemoteAddressModule : public Module
{
public:
    SocksRemoteAddressModule() : Module(s_name, s_help, socks_remote_address_params) { }

    bool set(const char*, Value& v, SnortConfig*) override
    {
        if ( v.is("~") )
            addr = v.get_string();
        return true;
    }

    ProfileStats* get_profile() const override
    { return &socks_remote_address_prof; }

    Usage get_usage() const override
    { return DETECT; }

    std::string addr;
};

//-------------------------------------------------------------------------
// socks_remote_address api
//-------------------------------------------------------------------------

static Module* socks_remote_address_mod_ctor() 
{ return new SocksRemoteAddressModule; }

static void socks_remote_address_mod_dtor(Module* m) 
{ delete m; }

// cppcheck-suppress constParameterCallback ; signature must match Module callback type
static IpsOption* socks_remote_address_ctor(Module* m, IpsInfo&)
{
    const SocksRemoteAddressModule* mod = static_cast<const SocksRemoteAddressModule*>(m);
    return new SocksRemoteAddressOption(mod->addr);
}

static void socks_remote_address_dtor(IpsOption* p) 
{ delete p; }

static const IpsApi socks_remote_address_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        socks_remote_address_mod_ctor,
        socks_remote_address_mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP | PROTO_BIT__UDP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    socks_remote_address_ctor,
    socks_remote_address_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// socks_remote_port - Match destination port
//-------------------------------------------------------------------------

#undef s_name
#undef s_help
#define s_name "socks_remote_port"
#define s_help "match SOCKS remote destination port"

static THREAD_LOCAL ProfileStats socks_remote_port_prof;

class SocksRemotePortOption : public IpsOption
{
public:
    SocksRemotePortOption(uint16_t p) : IpsOption(s_name), port(p) { }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;
    EvalStatus eval(Cursor&, Packet*) override;

private:
    uint16_t port;
};

uint32_t SocksRemotePortOption::hash() const
{
    uint32_t a = port, b = IpsOption::hash(), c = 0;
    mix(a, b, c);
    finalize(a, b, c);
    return c;
}

bool SocksRemotePortOption::operator==(const IpsOption& ips) const
{
    if ( !IpsOption::operator==(ips) )
        return false;

    const auto& rhs = static_cast<const SocksRemotePortOption&>(ips);
    return port == rhs.port;
}

IpsOption::EvalStatus SocksRemotePortOption::eval(Cursor&, Packet* p)
{
    // cppcheck-suppress unreadVariable
    RuleProfile profile(socks_remote_port_prof);

    if ( !p->flow )
        return NO_MATCH;

    const auto* fd = static_cast<const SocksFlowData*>(p->flow->get_flow_data(SocksFlowData::get_inspector_id()));
    if ( !fd )
        return NO_MATCH;

    // Only evaluate if target port has been set (SOCKS request parsed)
    // Port 0 is not a valid target port
    if ( fd->get_target_port() == 0 )
        return NO_MATCH;

    if ( fd->get_target_port() == port )
        return MATCH;

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// socks_remote_port module
//-------------------------------------------------------------------------

static const Parameter socks_remote_port_params[] =
{
    { "~port", Parameter::PT_PORT, nullptr, nullptr,
      "destination port to match" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class SocksRemotePortModule : public Module
{
public:
    SocksRemotePortModule() : Module(s_name, s_help, socks_remote_port_params) { }

    bool set(const char*, Value& v, SnortConfig*) override
    {
        assert(v.is("~port"));
        port = v.get_uint16();
        return true;
    }

    ProfileStats* get_profile() const override
    { return &socks_remote_port_prof; }

    Usage get_usage() const override
    { return DETECT; }

public:
    uint16_t port = 0;
};

//-------------------------------------------------------------------------
// socks_remote_port api
//-------------------------------------------------------------------------

static Module* socks_remote_port_mod_ctor() 
{ return new SocksRemotePortModule; }

static void socks_remote_port_mod_dtor(Module* m) 
{ delete m; }

// cppcheck-suppress constParameterCallback
static IpsOption* socks_remote_port_ctor(Module* p, IpsInfo&)
{
    const auto* m = static_cast<const SocksRemotePortModule*>(p);
    return new SocksRemotePortOption(m->port);
}

static void socks_remote_port_dtor(IpsOption* p)
{ delete p; }

static const IpsApi socks_remote_port_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        socks_remote_port_mod_ctor,
        socks_remote_port_mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP | PROTO_BIT__UDP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    socks_remote_port_ctor,
    socks_remote_port_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// plugin exports
//-------------------------------------------------------------------------

const BaseApi* ips_socks_version = &socks_version_api.base;
const BaseApi* ips_socks_state = &socks_state_api.base;
const BaseApi* ips_socks_command = &socks_command_api.base;
const BaseApi* ips_socks_address_type = &socks5_address_type_api.base;
const BaseApi* ips_socks_remote_address = &socks_remote_address_api.base;
const BaseApi* ips_socks_remote_port = &socks_remote_port_api.base;
