//--------------------------------------------------------------------------
// Copyright (C) 2014-2021 Cisco and/or its affiliates. All rights reserved.
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

// wiz_module.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "wiz_module.h"

#include "log/messages.h"
#include "trace/trace.h"

#include "curses.h"
#include "magic.h"

using namespace snort;
using namespace std;

THREAD_LOCAL const Trace* wizard_trace = nullptr;

//-------------------------------------------------------------------------
// wizard module
//-------------------------------------------------------------------------

static const Parameter wizard_hex_param[] =
{
    { "hex", Parameter::PT_STRING, nullptr, nullptr,
      "sequence of data with wild chars (?)" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter wizard_hexes_params[] =
{
    { "service", Parameter::PT_STRING, nullptr, nullptr,
      "name of service" },

    { "proto", Parameter::PT_SELECT, "tcp | udp", "tcp",
      "protocol to scan" },

    { "client_first", Parameter::PT_BOOL, nullptr, "true",
      "which end initiates data transfer" },

    { "to_server", Parameter::PT_LIST, wizard_hex_param, nullptr,
      "sequence of data with wild chars (?)" },

    { "to_client", Parameter::PT_LIST, wizard_hex_param, nullptr,
      "sequence of data with wild chars (?)" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter wizard_spell_param[] =
{
    { "spell", Parameter::PT_STRING, nullptr, nullptr,
      "sequence of data with wild cards (*)" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter wizard_spells_params[] =
{
    { "service", Parameter::PT_STRING, nullptr, nullptr,
      "name of service" },

    { "proto", Parameter::PT_SELECT, "tcp | udp", "tcp",
      "protocol to scan" },

    { "client_first", Parameter::PT_BOOL, nullptr, "true",
      "which end initiates data transfer" },

    { "to_server", Parameter::PT_LIST, wizard_spell_param, nullptr,
      "list of initial tokens with wild cards (*)" },

    { "to_client", Parameter::PT_LIST, wizard_spell_param, nullptr,
      "list of initial tokens with wild cards (*)" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter s_params[] =
{
    { "hexes", Parameter::PT_LIST, wizard_hexes_params, nullptr,
      "criteria for binary service identification" },

    { "spells", Parameter::PT_LIST, wizard_spells_params, nullptr,
      "criteria for text service identification" },

    { "curses", Parameter::PT_MULTI, "dce_smb | dce_udp | dce_tcp | sslv2", nullptr,
      "enable service identification based on internal algorithm" },

    { "max_search_depth", Parameter::PT_INT, "0:65535", "64",
      "maximum scan depth per flow" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

WizardModule::WizardModule() : Module(WIZ_NAME, WIZ_HELP, s_params) { }

WizardModule::~WizardModule()
{
    delete c2s_hexes;
    delete s2c_hexes;

    delete c2s_spells;
    delete s2c_spells;

    delete curses;
}

void WizardModule::set_trace(const Trace* trace) const
{ wizard_trace = trace; }

const TraceOption* WizardModule::get_trace_options() const
{
    static const TraceOption wizard_trace_options(nullptr, 0, nullptr);
    return &wizard_trace_options;
}

ProfileStats* WizardModule::get_profile() const
{ return &wizPerfStats; }

bool WizardModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("service") )
        service = v.get_string();

    // FIXIT-L implement proto and client_first
    else if ( v.is("proto") )
        return true;

    else if ( v.is("client_first") )
        return true;

    else if ( v.is("hex") || v.is("spell") )
    {
        if (c2s)
            c2s_patterns.emplace_back(v.get_string());
        else
            s2c_patterns.emplace_back(v.get_string());
    }
    else if ( v.is("curses") )
        curses->add_curse(v.get_string());

    else if ( v.is("max_search_depth") )
        max_search_depth = v.get_uint16();

    return true;
}

bool WizardModule::begin(const char* fqn, int idx, SnortConfig*)
{
    if ( !strcmp(fqn, "wizard") )
    {
        c2s_hexes = new HexBook;
        s2c_hexes = new HexBook;

        c2s_spells = new SpellBook;
        s2c_spells = new SpellBook;

        curses = new CurseBook;
    }
    else if ( !strcmp(fqn, "wizard.hexes") || !strcmp(fqn, "wizard.spells") )
    {
        if ( idx > 0 )
        {
            service.clear();
            c2s_patterns.clear();
            s2c_patterns.clear();
        }
    }
    else if ( !strcmp(fqn, "wizard.hexes.to_client") || !strcmp(fqn, "wizard.spells.to_client") )
        c2s = false;

    else if ( !strcmp(fqn, "wizard.hexes.to_server") || !strcmp(fqn, "wizard.spells.to_server") )
        c2s = true;

    return true;
}

static bool add_spells(MagicBook* b, const string& service, const vector<string>& patterns, bool hex)
{
    for ( const auto& p : patterns )
    {
        const char* val = service.c_str();
        if ( !b->add_spell(p.c_str(), val) )
        {
            if ( !val )
            {
                ParseError("Invalid %s '%s' for service '%s'",
                    hex ? "hex" : "spell", p.c_str(), service.c_str());
                return false;
            }
            else if ( service != val )
            {
                ParseWarning(WARN_CONF, "%s '%s' for service '%s' already exists for service '%s'",
                    hex ? "Hex" : "Spell", p.c_str(), service.c_str(), val);
            }
            else
            {
                ParseWarning(WARN_CONF, "Duplicate %s '%s' for service '%s'",
                    hex ? "hex" : "spell", p.c_str(), val);
            }
        }
    }
    return true;
}

bool WizardModule::end(const char* fqn, int idx, SnortConfig*)
{
    if ( !strcmp(fqn, "wizard") )
    {
        service.clear();
        c2s_patterns.clear();
    }
    else if ( !strcmp(fqn, "wizard.hexes") )
    {
        if ( idx > 0 )
        {
            // Validate the hex
            if ( service.empty() )
            {
                ParseError("Hexes must have a service name");
                return false;
            }
            if ( c2s_patterns.empty() && s2c_patterns.empty() )
            {
                ParseError("Hexes must have at least one pattern");
                return false;
            }
            if ( !add_spells(c2s_hexes, service, c2s_patterns, true) )
                return false;
            if ( !add_spells(s2c_hexes, service, s2c_patterns, true) )
                return false;
        }
    }
    else if ( !strcmp(fqn, "wizard.spells") )
    {
        if ( idx > 0 )
        {
            // Validate the spell
            if ( service.empty() )
            {
                ParseError("Spells must have a service name");
                return false;
            }
            if ( c2s_patterns.empty() && s2c_patterns.empty() )
            {
                ParseError("Spells must have at least one pattern");
                return false;
            }
            if ( !add_spells(c2s_spells, service, c2s_patterns, false) )
                return false;
            if ( !add_spells(s2c_spells, service, s2c_patterns, false) )
                return false;
        }
    }

    return true;
}

MagicBook* WizardModule::get_book(bool c2s, bool hex)
{
    int k = c2s ? 1 : 0;
    k |= (hex ? 2 : 0);

    MagicBook* b = nullptr;

    switch ( k )
    {
    case 0:
        b = s2c_spells;
        s2c_spells = nullptr;
        break;

    case 1:
        b = c2s_spells;
        c2s_spells = nullptr;
        break;

    case 2:
        b = s2c_hexes;
        s2c_hexes = nullptr;
        break;

    case 3:
        b = c2s_hexes;
        c2s_hexes = nullptr;
        break;
    }
    return b;
}

CurseBook* WizardModule::get_curse_book()
{
    CurseBook* b = curses;
    curses = nullptr;
    return b;
}

const PegInfo* WizardModule::get_pegs() const
{ return wiz_pegs; }

PegCount* WizardModule::get_counts() const
{ return (PegCount*)&tstats; }

