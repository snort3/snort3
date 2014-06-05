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

// template_module.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "codecs/template_module.h"


static const Parameter codec_params[] =
{
    { "parameter1", Parameter::PT_BOOL, nullptr, "false",
      "This is a boolean parameter" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};


// rules which will loaded into snort. 
// You can now reference these rules by calling a codec_event
// in your main codec's functions
static const RuleMap codec_rules[] =
{
    { SID, "(" CODEC_NAME ") alert message" },
    { 0, nullptr }
};

//-------------------------------------------------------------------------
// rpc module
//-------------------------------------------------------------------------

NameCodec::NameCodec() : DecodeModule(CODEC_NAME, codec_params, codec_rules)
{ }

bool NameCodec::set(const char*, Value& v, SnortConfig* sc)
{
    if ( v.is("parameter1") )
        option1 = v.get_bool();

    else
        return false;

    return true;
}

bool NameCodec::begin(const char*, int, SnortConfig*)
{
    option1 = false;
    return true;
}
