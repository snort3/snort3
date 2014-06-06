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

// cd_arp_module.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "codecs/root/cd_tr_module.h"


static const Parameter trk_params[] =
{
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};


static const RuleMap trk_rules[] =
{
    { DECODE_BAD_TRH, "(" CD_TR_NAME ") Bad Token Ring Header" },
    { DECODE_BAD_TR_ETHLLC, "(" CD_TR_NAME ") Bad Token Ring ETHLLC Header" },
    { DECODE_BAD_TR_MR_LEN, "(" CD_TR_NAME ") Bad Token Ring MRLENHeader" },
    { DECODE_BAD_TRHMR, "(" CD_TR_NAME ") Bad Token Ring MR Header" },
    { 0, nullptr }
};

//-------------------------------------------------------------------------
// token ring module
//-------------------------------------------------------------------------

TrCodecModule::TrCodecModule() : DecodeModule(CD_TR_NAME, trk_params, trk_rules)
{ }

bool TrCodecModule::set(const char*, Value&, SnortConfig*)
{
    return true;
}
