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

// wiz_module.cc author Russ Combs <rucombs@cisco.com>

#include "wiz_module.h"

#include <assert.h>
#include <string.h>

#include <string>
using namespace std;

#include "wizard.h"
#include "magic.h"

static const char* s_name = "wizard";

//-------------------------------------------------------------------------
// wizard module
//-------------------------------------------------------------------------

static const Parameter wizard_hex_params[] =
{
    { "service", Parameter::PT_STRING, nullptr, nullptr,
      "name of service" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter wizard_hexes_params[] =
{
    { "service", Parameter::PT_STRING, nullptr, nullptr,
      "name of service" },

    { "proto", Parameter::PT_SELECT, "tcp | udp", "tcp",
      "name of service" },

    { "client_first", Parameter::PT_BOOL, nullptr, "true",
      "which end initiates data transfer" },

    { "to_server", Parameter::PT_LIST, wizard_hex_params, nullptr,
      "sequence of offsets and data" },

    { "to_client", Parameter::PT_LIST, wizard_hex_params, nullptr,
      "sequence of offsets and data" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter wizard_spell_params[] =
{
    { "service", Parameter::PT_STRING, nullptr, nullptr,
      "name of service" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter wizard_spells_params[] =
{
    { "service", Parameter::PT_STRING, nullptr, nullptr,
      "name of service" },

    { "proto", Parameter::PT_SELECT, "tcp | udp", "tcp",
      "name of service" },

    { "client_first", Parameter::PT_BOOL, nullptr, "true",
      "which end initiates data transfer" },

    { "to_server", Parameter::PT_LIST, wizard_spell_params, nullptr,
      "sequence of offsets and data" },

    { "to_client", Parameter::PT_LIST, wizard_spell_params, nullptr,
      "sequence of offsets and data" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter wizard_params[] =
{
    { "hexes", Parameter::PT_LIST, wizard_hexes_params, nullptr,
      "criteria for binary service identification" },

    { "spells", Parameter::PT_LIST, wizard_spells_params, nullptr,
      "criteria for text service identification" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

WizardModule::WizardModule() : Module(s_name, wizard_params)
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

bool WizardModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("service") )
        return true;

    else if ( v.is("proto") )
        return true;

    else if ( v.is("client_first") )
        return true;

    else if ( v.is("to_server") )
    {
        if ( hex )
            c2s_hexes->add_spell(v.get_string());
        else
            c2s_spells->add_spell(v.get_string());
    }
    else if ( v.is("to_client") )
    {
        if ( hex )
            s2c_hexes->add_spell(v.get_string());
        else
            s2c_spells->add_spell(v.get_string());
    }
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

        c2s_spells = new HexBook;
        s2c_spells = new HexBook;
    }
    else if ( !strcmp(fqn, "hexes") )
        hex = true;

    else if ( !strcmp(fqn, "spells") )
        hex = false;

    return true;
}

bool WizardModule::end(const char*, int, SnortConfig*)
{
    return true;
}

MagicBook* WizardModule::get_book(bool c2s, bool hex)
{
    if ( c2s )
        return hex ? c2s_hexes : c2s_spells;

    return hex ? s2c_hexes : s2c_spells;
}

