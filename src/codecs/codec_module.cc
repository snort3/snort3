//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
// codec_module.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "codecs/codec_module.h"

#include "main/snort_debug.h"

using namespace snort;

#define codec_module_help \
    "general decoder rules"

Trace TRACE_NAME(decode);

static const Parameter s_params[] = {{ nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }};

CodecModule::CodecModule() : Module("decode", codec_module_help, s_params, false, &TRACE_NAME(decode))
{ }

bool CodecModule::set(const char* fqn, Value& v, SnortConfig* sc)
{
    return Module::set(fqn, v, sc);
}

static const RuleMap general_decode_rules[] =
{
    { DECODE_IP_BAD_PROTO, "bad IP protocol" },
    { DECODE_IP_MULTIPLE_ENCAPSULATION,
        "two or more IP (v4 and/or v6) encapsulation layers present" },
    { DECODE_ZERO_LENGTH_FRAG, "fragment with zero length" },
    { DECODE_BAD_TRAFFIC_LOOPBACK, "loopback IP" },
    { DECODE_BAD_TRAFFIC_SAME_SRCDST, "same src/dst IP" },
    { DECODE_IP_UNASSIGNED_PROTO, "unassigned/reserved IP protocol" },
    { DECODE_TOO_MANY_LAYERS, "too many protocols present" },
    { DECODE_BAD_ETHER_TYPE, "ether type out of range" },
    { 0, nullptr },
};

const RuleMap* CodecModule::get_rules() const
{ return general_decode_rules; }

