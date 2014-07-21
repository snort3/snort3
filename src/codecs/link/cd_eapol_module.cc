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

// cd_eapol_module.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "codecs/link/cd_eapol_module.h"

static const RuleMap eapol_rules[] =
{
    { DECODE_EAPOL_TRUNCATED, "(" CD_EAPOL_NAME ") Truncated EAP Header" },
    { DECODE_EAPKEY_TRUNCATED, "(" CD_EAPOL_NAME ") EAP Key Truncated" },
    { DECODE_EAP_TRUNCATED, "(" CD_EAPOL_NAME ") EAP Header Truncated" },
    { 0, nullptr }
};

//-------------------------------------------------------------------------
// rpc module
//-------------------------------------------------------------------------

EapolModule::EapolModule() : DecodeModule(CD_EAPOL_NAME)
{ }

const RuleMap* EapolModule::get_rules() const
{ return eapol_rules; }

