//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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
// file_module.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "file_module.h"

using namespace snort;
using namespace std;

//-------------------------------------------------------------------------
// stream_file module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "upload", Parameter::PT_BOOL, nullptr, "false",
      "indicate file transfer direction" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

StreamFileModule::StreamFileModule() :
    Module(MOD_NAME, MOD_HELP, s_params) { }


bool StreamFileModule::begin(const char*, int, SnortConfig*)
{
    upload = false;
    return true;
}

bool StreamFileModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("upload") )
        upload = v.get_bool();

    else
        return false;

    return true;
}

