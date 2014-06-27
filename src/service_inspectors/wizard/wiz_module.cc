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

static const char* s_name = "wizard";

//-------------------------------------------------------------------------
// wizard module
//-------------------------------------------------------------------------

static const Parameter wizard_params[] =
{
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

WizardModule::WizardModule() : Module(s_name, wizard_params)
{ }

WizardModule::~WizardModule()
{ }

bool WizardModule::set(const char*, Value&, SnortConfig*)
{
    //if ( v.is("type") )
    //    work->type = v.get_string();

    //else
    //    return false;

    return true;
}

bool WizardModule::begin(const char*, int, SnortConfig*)
{
    return true;
}

bool WizardModule::end(const char*, int, SnortConfig*)
{
    return true;
}

