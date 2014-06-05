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

// cd_gre_module.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "codecs/ip/cd_gre_module.h"


static const Parameter gre_params[] =
{
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};


static const RuleMap gre_rules[] =
{
    { DECODE_GRE_DGRAM_LT_GREHDR, "(" CD_GRE_NAME ") GRE header length > payload length" },
    { DECODE_GRE_MULTIPLE_ENCAPSULATION, "(" CD_GRE_NAME ") Multiple encapsulations in packet" },
    { DECODE_GRE_INVALID_VERSION, "(" CD_GRE_NAME ") Invalid GRE version" },
    { DECODE_GRE_INVALID_HEADER, "(" CD_GRE_NAME ") Invalid GRE header" },
    { DECODE_GRE_V1_INVALID_HEADER, "(" CD_GRE_NAME ") Invalid GRE v.1 PPTP header" },
    { DECODE_GRE_TRANS_DGRAM_LT_TRANSHDR, "(" CD_GRE_NAME ") GRE Trans header length > payload length" },
    { 0, nullptr }
};

//-------------------------------------------------------------------------
// rpc module
//-------------------------------------------------------------------------

GreModule::GreModule() : DecodeModule(CD_GRE_NAME, gre_params, gre_rules)
{ }

bool GreModule::set(const char*, Value&, SnortConfig*)
{
    return true;
}
