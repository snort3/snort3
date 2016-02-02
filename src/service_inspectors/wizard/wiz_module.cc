//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

#include "wiz_module.h"

#include <assert.h>
#include <string.h>

#include <string>
using namespace std;

#include "magic.h"

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

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

WizardModule::WizardModule() : Module(WIZ_NAME, WIZ_HELP, s_params)
{
    c2s_hexes = nullptr;
    s2c_hexes = nullptr;
    c2s_spells = nullptr;
    s2c_spells = nullptr;
}

WizardModule::~WizardModule()
{
    delete c2s_hexes;
    delete s2c_hexes;

    delete c2s_spells;
    delete s2c_spells;
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

    else if ( v.is("hex") )
        spells.push_back(v.get_string());

    else if ( v.is("spell") )
        spells.push_back(v.get_string());

    else
        return false;

    return true;
}

bool WizardModule::begin(const char* fqn, int, SnortConfig*)
{
    if ( !strcmp(fqn, "wizard") )
    {
        c2s_hexes = new HexBook;
        s2c_hexes = new HexBook;

        c2s_spells = new SpellBook;
        s2c_spells = new SpellBook;
    }
    else if ( !strcmp(fqn, "wizard.hexes") )
        hex = true;

    else if ( !strcmp(fqn, "wizard.spells") )
        hex = false;

    else if ( !strcmp(fqn, "wizard.hexes.to_client") )
        c2s = false;

    else if ( !strcmp(fqn, "wizard.spells.to_client") )
        c2s = false;

    else if ( !strcmp(fqn, "wizard.hexes.to_server") )
        c2s = true;

    else if ( !strcmp(fqn, "wizard.spells.to_server") )
        c2s = true;

    return true;
}

void WizardModule::add_spells(MagicBook* b, string& service)
{
    for ( auto p : spells )
        b->add_spell(p.c_str(), service.c_str());
}

bool WizardModule::end(const char*, int idx, SnortConfig*)
{
    if ( !idx )
        return true;

    if ( hex )
    {
        if ( c2s )
            add_spells(c2s_hexes, service);
        else
            add_spells(s2c_hexes, service);
    }
    else
    {
        if ( c2s )
            add_spells(c2s_spells, service);
        else
            add_spells(s2c_spells, service);
    }
    spells.clear();
    service.clear();

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

const PegInfo* WizardModule::get_pegs() const
{ return wiz_pegs; }

PegCount* WizardModule::get_counts() const
{ return (PegCount*)&tstats; }

