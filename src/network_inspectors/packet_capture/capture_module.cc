//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

// capture_module.cc author Carter Waxman <rucombs@cisco.com>

#include "capture_module.h"

#include "profiler/profiler.h"
#include "utils/util.h"

const PegInfo cap_names[] =
{
    { "processed", "packets processed against filter" },
    { "captured", "packets matching dumped after matching filter" },
    { nullptr, nullptr }
};

THREAD_LOCAL CaptureStats cap_count_stats;
THREAD_LOCAL ProfileStats cap_prof_stats;

static const Parameter s_params[] =
{
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

CaptureModule::CaptureModule() :
    Module(CAPTURE_NAME, CAPTURE_HELP, s_params)
{ }

ProfileStats* CaptureModule::get_profile() const
{ return &cap_prof_stats; }

bool CaptureModule::set(const char*, Value&, SnortConfig*)
{
    return true;
}

void CaptureModule::get_config(CaptureConfig& cfg)
{
    cfg = config;
}

const PegInfo* CaptureModule::get_pegs() const
{ return cap_names; }

PegCount* CaptureModule::get_counts() const
{ return (PegCount*)&cap_count_stats; }

