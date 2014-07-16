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

// cd_erspan2_module.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "codecs/link/cd_erspan2_module.h"

static const RuleMap erspan2_rules[] =
{
    { DECODE_ERSPAN_HDR_VERSION_MISMATCH, "(codec_erspan) ERSpan Header version mismatch" },
    { DECODE_ERSPAN2_DGRAM_LT_HDR, "(" CD_ERSPAN2_NAME ") captured < ERSpan Type2 Header Length" },
    { 0, nullptr }
};

//-------------------------------------------------------------------------
// rpc module
//-------------------------------------------------------------------------

Erspan2Module::Erspan2Module() : DecodeModule(CD_ERSPAN2_NAME)
{ }

const RuleMap* Erspan2Module::get_rules() const
{ return erspan2_rules; }

