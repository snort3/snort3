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

// Major rewrite: Hui Cao <hcao@sourcefire.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ips_flowbits.h"

#include <unordered_map>

#include "detection/treenodes.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hash_defs.h"
#include "hash/hash_key_operations.h"
#include "helpers/bitop.h"
#include "log/messages.h"
#include "protocols/packet.h"
#include "profiler/profiler.h"
#include "utils/sflsq.h"
#include "utils/util.h"

using namespace snort;

#define s_name "flowbits"

struct FlowBit
{
    uint16_t id = 65535;
    uint16_t sets = 0;
    uint16_t checks = 0;

    bool is_new()
    { return id == 65535; }
};

static std::vector<std::string> bit_keys;
static std::unordered_map<std::string, FlowBit> bit_map;
static THREAD_LOCAL ProfileStats flowbits_profile;

//--------------------------------------------------------------------------
// flowbits option config
//--------------------------------------------------------------------------

struct FlowBitCheck
{
    enum Op { SET, UNSET, IS_SET, IS_NOT_SET, NO_ALERT };

    FlowBitCheck(Op t) : type(t) { }
    bool validate();

    bool is_setter() const
    { return type == SET or type == UNSET; }

    bool is_checker() const
    { return type == IS_SET or type == IS_NOT_SET; }

    void add(uint16_t);

    std::vector<uint16_t> ids;
    uint16_t max = 0;
    bool or_bits = false;
    Op type;
};

void FlowBitCheck::add(uint16_t id)
{
    ids.push_back(id);
    if ( id > max )
        max = id;
}

bool FlowBitCheck::validate()
{
    switch ( type )
    {
    case SET:
        if ( !or_bits and !ids.empty() )
            return true;

        ParseError("%s: set uses syntax: flowbits:set,bit[&bit].", s_name);
        break;

    case UNSET:
        if ( !or_bits and !ids.empty() )
            return true;

        ParseError("%s: unset uses syntax: flowbits:unset,bit[&bit].", s_name);
        break;

    case IS_SET:
        if ( !ids.empty() )
            return true;

        ParseError("%s: isset uses syntax: flowbits:isset,bit[&bit] OR "
            "flowbits:isset,bit[|bit].", s_name);
        break;

    case IS_NOT_SET:
        if ( !ids.empty() )
            return true;

        ParseError("%s: isnotset uses syntax: flowbits:isnotset,bit[&bit] OR "
            "flowbits:isnotset,bit[|bit]", s_name);
        break;

    case NO_ALERT:
        if ( ids.empty() )
            return true;

        ParseError("%s: noalert uses syntax: flowbits:noalert.", s_name);
        break;
    }
    return false;
}

//--------------------------------------------------------------------------
// flowbits option config
//--------------------------------------------------------------------------

class FlowBitsOption : public IpsOption
{
public:
    FlowBitsOption(FlowBitCheck* c) :
        IpsOption(s_name, RULE_OPTION_TYPE_FLOWBIT), config(c)
    { }

    ~FlowBitsOption() override;

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

    bool is_setter() const
    { return config->is_setter(); }

    bool is_checker() const
    { return config->is_checker(); }

    void get_dependencies(bool& set, std::vector<std::string>& bits);

private:
    bool is_set(BitOp*);

private:
    FlowBitCheck* config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

FlowBitsOption::~FlowBitsOption()
{
    delete config;
}

uint32_t FlowBitsOption::hash() const
{
    uint32_t a = config->or_bits ? 1 : 0;
    uint32_t b = config->type;
    uint32_t c = IpsOption::hash();

    mix(a,b,c);

    unsigned i;
    unsigned j = 0;

    for (i = 0, j = 0; i < config->ids.size(); i++, j++)
    {
        if (j >= 3)
        {
            a += config->ids[i - 2];
            b += config->ids[i - 1];
            c += config->ids[i];
            mix(a,b,c);
            j -= 3;
        }
    }
    if (1 == j)
    {
        a += config->ids[config->ids.size() - 1];
        b += config->ids.size();
    }
    else if (2 == j)
    {
        a += config->ids[config->ids.size() - 2];
        b += config->ids[config->ids.size() - 1]|config->ids.size() << 16;
    }

    finalize(a,b,c);
    return c;
}

bool FlowBitsOption::operator==(const IpsOption& ips) const
{
    if ( !IpsOption::operator==(ips) )
        return false;

    const FlowBitsOption& rhs = (const FlowBitsOption&)ips;

    if ( (config->ids.size() != rhs.config->ids.size()) or
            (config->or_bits != rhs.config->or_bits) or
            (config->type != rhs.config->type) )
        return false;

    for ( unsigned i = 0; i < config->ids.size(); i++ )
    {
        if (config->ids[i] != rhs.config->ids[i])
            return false;
    }

    return true;
}

IpsOption::EvalStatus FlowBitsOption::eval(Cursor&, Packet* p)
{
    RuleProfile profile(flowbits_profile);

    if ( !p->flow )
        return IpsOption::NO_MATCH;

    BitOp* bitop = p->flow->bitop;

    // do ops that don't require a bit
    switch ( config->type )
    {
    case FlowBitCheck::SET:
        break;

    case FlowBitCheck::UNSET:
        if ( !bitop )
            return IpsOption::MATCH;

        for ( auto id : config->ids )
            bitop->clear(id);

        return IpsOption::MATCH;

    case FlowBitCheck::IS_SET:
        if ( !bitop )
            return IpsOption::FAILED_BIT;

        if ( is_set(bitop) )
            return IpsOption::MATCH;

        return IpsOption::FAILED_BIT;

    case FlowBitCheck::IS_NOT_SET:
        if ( !bitop or !is_set(bitop) )
            return IpsOption::MATCH;

        return IpsOption::FAILED_BIT;

    case FlowBitCheck::NO_ALERT:
        return IpsOption::NO_ALERT;
    }

    // do ops that require a bit (set)
    if ( !bitop )
        bitop = p->flow->bitop = new BitOp(config->max);

    for ( auto id : config->ids )
        bitop->set(id);

    return IpsOption::MATCH;
}

bool FlowBitsOption::is_set(BitOp* bitop)
{
    return config->or_bits ?
        std::any_of(config->ids.cbegin(), config->ids.cend(),
            [&bitop](uint16_t id){ return bitop->is_set(id); })
        :
        std::none_of(config->ids.cbegin(), config->ids.cend(),
            [&bitop](uint16_t id){ return !bitop->is_set(id); });
}

void FlowBitsOption::get_dependencies(bool& set, std::vector<std::string>& bits)
{
    set = config->is_setter();

    for ( auto id : config->ids )
    {
        assert(id < bit_keys.size());
        bits.emplace_back(bit_keys[id]);
    }
}

//-------------------------------------------------------------------------
// public methods
//-------------------------------------------------------------------------

bool flowbits_setter(void* option_data)
{
    FlowBitsOption* p = (FlowBitsOption*)option_data;
    return p->is_setter();
}

void get_flowbits_dependencies(void* option_data, bool& set, std::vector<std::string>& bits)
{
    FlowBitsOption* p = (FlowBitsOption*)option_data;
    p->get_dependencies(set, bits);
}

void flowbits_counts(unsigned& total, unsigned& unchecked, unsigned& unset)
{
    unchecked = unset = 0;

    for ( const auto& it : bit_map )
    {
        if ((it.second.sets > 0) and (it.second.checks == 0))
        {
            ParseWarning(WARN_FLOWBITS, "%s key '%s' is set but not checked.",
                s_name, it.first.c_str());
            unchecked++;
        }
        else if ((it.second.checks > 0) and (it.second.sets == 0))
        {
            ParseWarning(WARN_FLOWBITS, "%s key '%s' is checked but not set.",
                s_name, it.first.c_str());
            unset++;
        }
    }

    total = bit_map.size();
}

//-------------------------------------------------------------------------
// parsing methods
//-------------------------------------------------------------------------

static FlowBit* get_bit(
    const char* bit, FlowBitCheck* check)
{
    FlowBit& flow_bit = bit_map[bit];

    if ( flow_bit.is_new() )
    {
        flow_bit.id = bit_map.size() - 1;
        bit_keys.emplace_back(bit);
    }

    if ( check->is_setter() )
        flow_bit.sets++;

    else if ( check->is_checker() )
        flow_bit.checks++;

    return &flow_bit;
}

static bool parse_flowbits(const char* flowbits_names, FlowBitCheck* check)
{
    assert(flowbits_names);
    FlowBit* flow_bit;

    if ( strchr(flowbits_names, '|') )
    {
        if ( strchr(flowbits_names, '&') )
        {
            ParseError("%s: tag id opcode '|' and '&' are used together.", s_name);
            return false;
        }
        std::string bits = flowbits_names;
        std::replace(bits.begin(), bits.end(), '|', ' ');
        std::stringstream ss(bits);
        std::string tok;

        while ( ss >> tok )
        {
            flow_bit = get_bit(tok.c_str(), check);
            check->add(flow_bit->id);
        }
        check->or_bits = true;
    }
    else if ( strchr(flowbits_names, '&') )
    {
        std::string bits = flowbits_names;
        std::replace(bits.begin(), bits.end(), '&', ' ');
        std::stringstream ss(bits);
        std::string tok;

        while ( ss >> tok )
        {
            flow_bit = get_bit(tok.c_str(), check);
            check->add(flow_bit->id);
        }
        check->or_bits = false;
    }
    else
    {
        flow_bit = get_bit(flowbits_names, check);
        check->add(flow_bit->id);
    }
    return true;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~op", Parameter::PT_ENUM, "set | unset | isset | isnotset | noalert", nullptr,
      "bit operation or noalert (no bits)" },

    { "~bits", Parameter::PT_STRING, nullptr, nullptr,
      "bit [|bit]* or bit [&bit]*" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to set and test arbitrary boolean flags"

class FlowbitsModule : public Module
{
public:
    FlowbitsModule() : Module(s_name, s_help, s_params) { }
    ~FlowbitsModule() override { delete fbc; }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &flowbits_profile; }

    Usage get_usage() const override
    { return DETECT; }

    FlowBitCheck* get_data();

public:
    FlowBitCheck::Op op = FlowBitCheck::Op::SET;
    std::string bits;
    FlowBitCheck* fbc = nullptr;
};

bool FlowbitsModule::begin(const char*, int, SnortConfig*)
{
    delete fbc;
    bits.clear();
    return true;
}

bool FlowbitsModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("~op") )
        op = static_cast<FlowBitCheck::Op>(v.get_uint8());

    else if ( v.is("~bits") )
        bits = v.get_string();

    return true;
}

bool FlowbitsModule::end(const char*, int, SnortConfig*)
{
    fbc = new FlowBitCheck(op);
    bool ok = true;

    if ( fbc->is_setter() or fbc->is_checker() )
        ok = parse_flowbits(bits.c_str(), fbc);

    ok = ok and fbc->validate();
    return ok;
}

FlowBitCheck* FlowbitsModule::get_data()
{
    FlowBitCheck* tmp = fbc;
    fbc = nullptr;
    return tmp;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new FlowbitsModule;
}

static void mod_dtor(Module* m)
{
    FlowbitsModule* fb = (FlowbitsModule*)m;
    delete fb;
}

static IpsOption* flowbits_ctor(Module* p, OptTreeNode* otn)
{
    FlowbitsModule* m = (FlowbitsModule*)p;
    FlowBitCheck* fbc = m->get_data();
    FlowBitsOption* opt = new FlowBitsOption(fbc);

    if ( opt->is_checker() )
        otn->set_flowbits_check();

    return opt;
}

static void flowbits_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi flowbits_api =
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
        mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, 0,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    flowbits_ctor,
    flowbits_dtor,
    nullptr
};

const BaseApi* ips_flowbits = &flowbits_api.base;

