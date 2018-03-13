//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

// dns_module.cc author Bhagyashree Bantwal <bbantwal@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dns_module.h"

using namespace snort;
using namespace std;

#define DNS_EVENT_OBSOLETE_TYPES_STR \
    "obsolete DNS RR types"
#define DNS_EVENT_EXPERIMENTAL_TYPES_STR \
    "experimental DNS RR types"
#define DNS_EVENT_RDATA_OVERFLOW_STR \
    "DNS client rdata txt overflow"

static const Parameter s_params[] =
{
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap dns_rules[] =
{
    { DNS_EVENT_OBSOLETE_TYPES, DNS_EVENT_OBSOLETE_TYPES_STR },
    { DNS_EVENT_EXPERIMENTAL_TYPES, DNS_EVENT_EXPERIMENTAL_TYPES_STR },
    { DNS_EVENT_RDATA_OVERFLOW, DNS_EVENT_RDATA_OVERFLOW_STR },

    { 0, nullptr }
};

//-------------------------------------------------------------------------
// dns module
//-------------------------------------------------------------------------

DnsModule::DnsModule() : Module(DNS_NAME, DNS_HELP, s_params)
{ }

const RuleMap* DnsModule::get_rules() const
{ return dns_rules; }

const PegInfo* DnsModule::get_pegs() const
{ return dns_peg_names; }

PegCount* DnsModule::get_counts() const
{ return (PegCount*)&dnsstats; }

ProfileStats* DnsModule::get_profile() const
{ return &dnsPerfStats; }

