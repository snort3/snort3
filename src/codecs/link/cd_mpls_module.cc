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

// cd_mpls_module.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "codecs/link/cd_mpls_module.h"
#include "main/snort_config.h"
#include "main/snort.h"

static const Parameter mpls_params[] =
{
    { "enable_mpls_multicast", Parameter::PT_BOOL, nullptr, "false",
      "enables support for MPLS multicast" },

    { "enable_mpls_overlapping_ip", Parameter::PT_BOOL, nullptr, "false",
      "enable if private network addresses overlap and must be differentiated by MPLS label(s)" },

    { "max_mpls_label_chain_len", Parameter::PT_INT, "-1:", "-1",
      "set MPLS stack depth" },

    { "mpls_payload_type", Parameter::PT_ENUM, "eth | ip4 | ip6", "ip4",
      "set encapsulated payload type" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};


// rules which will loaded into snort. 
// You can now reference these rules by calling a codec_event
// in your main codec's functions
static const RuleMap mpls_rules[] =
{
    { DECODE_BAD_MPLS, "(" CD_MPLS_NAME ") Bad MPLS Frame" },
    { DECODE_BAD_MPLS_LABEL0, "(" CD_MPLS_NAME ") MPLS Label 0 Appears in Nonbottom Header" },
    { DECODE_BAD_MPLS_LABEL1, "(" CD_MPLS_NAME ") MPLS Label 1 Appears in Bottom Header" },
    { DECODE_BAD_MPLS_LABEL2, "(" CD_MPLS_NAME ") MPLS Label 2 Appears in Nonbottom Header" },
    { DECODE_BAD_MPLS_LABEL3, "(" CD_MPLS_NAME ") MPLS Label 3 Appears in Header" },
    { DECODE_MPLS_RESERVED_LABEL, "(" CD_MPLS_NAME ") MPLS Label 4, 5,.. or 15 Appears in Header" },
    { DECODE_MPLS_LABEL_STACK, "(" CD_MPLS_NAME ") Too Many MPLS headers" },
    { 0, nullptr }
};

//-------------------------------------------------------------------------
// mpls module
//-------------------------------------------------------------------------

MplsModule::MplsModule() : DecodeModule(CD_MPLS_NAME, mpls_params)
{ }

const RuleMap* MplsModule::get_rules() const
{ return mpls_rules; }

bool MplsModule::set(const char*, Value& v, SnortConfig* sc)
{ 
    if ( v.is("enable_mpls_multicast") )
    {
        if ( v.get_bool() )
            sc->run_flags |= RUN_FLAG__MPLS_MULTICAST; // FIXIT move to existing bitfield
    }
    else if ( v.is("enable_mpls_overlapping_ip") )
    {
        if ( v.get_bool() )
            sc->run_flags |= RUN_FLAG__MPLS_OVERLAPPING_IP; // FIXIT move to existing bitfield
    }
    else if ( v.is("max_mpls_label_chain_len") )
        sc->mpls_stack_depth = v.get_long();

    else if ( v.is("mpls_payload_type") )
        sc->mpls_payload_type = v.get_long() + 1;

    else
        return false;

    return true;
}

