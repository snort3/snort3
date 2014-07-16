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

// cd_gtp_module.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "codecs/misc/cd_gtp_module.h"

static const RuleMap gtp_rules[] =
{

    { DECODE_GTP_MULTIPLE_ENCAPSULATION, "(" CD_GTP_NAME ") Two or more GTP encapsulation layers present" },
    { DECODE_GTP_BAD_LEN, "(" CD_GTP_NAME ") GTP header length is invalid" },
    { 0, nullptr }
};

//-------------------------------------------------------------------------
// rpc module
//-------------------------------------------------------------------------

GtpModule::GtpModule() : DecodeModule(CD_GTP_NAME)
{ }

const RuleMap* GtpModule::get_rules() const
{ return gtp_rules; }

