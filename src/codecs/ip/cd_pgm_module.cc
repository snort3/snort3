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

// cd_pgm_module.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "codecs/ip/cd_pgm_module.h"

static const RuleMap pgm_rules[] =
{
    { DECODE_PGM_NAK_OVERFLOW, "(" CD_PGM_NAME ") BAD-TRAFFIC PGM nak list overflow attempt" },
    { 0, nullptr }
};

//-------------------------------------------------------------------------
// rpc module
//-------------------------------------------------------------------------

PgmModule::PgmModule() : DecodeModule(CD_PGM_NAME)
{ }

const RuleMap* PgmModule::get_rules() const
{ return pgm_rules; }

