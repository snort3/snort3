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

// cd_ah_module.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "codecs/ip/cd_auth_module.h"


static const Parameter ah_params[] =
{
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};


static const RuleMap ah_rules[] =
{
    { DECODE_AUTH_HDR_TRUNC, "(" CD_AUTH_NAME ") Truncated authentication header"},
    { DECODE_AUTH_HDR_BAD_LEN, "(" CD_AUTH_NAME ") Bad authentication header length"},
    { 0, nullptr }
};

//-------------------------------------------------------------------------
// rpc module
//-------------------------------------------------------------------------

AhModule::AhModule() : DecodeModule(CD_AUTH_NAME, ah_params, ah_rules)
{ }

bool AhModule::set(const char*, Value&, SnortConfig*)
{
    return true;
}
