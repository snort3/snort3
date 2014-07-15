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

// cd_igmp_module.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "codecs/ip/cd_igmp_module.h"

static const RuleMap igmp_rules[] =
{
    { DECODE_IGMP_OPTIONS_DOS, "(" CD_IGMP_NAME ") DOS IGMP IP Options validation attempt" },
    { 0, nullptr }
};

//-------------------------------------------------------------------------
// rpc module
//-------------------------------------------------------------------------

IgmpModule::IgmpModule() : DecodeModule(CD_IGMP_NAME)
{ }

const RuleMap* IgmpModule::get_rules() const
{ return igmp_rules; }

