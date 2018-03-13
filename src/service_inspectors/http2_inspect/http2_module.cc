//--------------------------------------------------------------------------
// Copyright (C) 2018-2018 Cisco and/or its affiliates. All rights reserved.
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
// http2_module.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http2_module.h"

using namespace snort;
using namespace Http2Enums;

const Parameter Http2Module::http2_params[] =
{
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

THREAD_LOCAL ProfileStats Http2Module::http2_profile;

ProfileStats* Http2Module::get_profile() const
{ return &http2_profile; }

THREAD_LOCAL PegCount Http2Module::peg_counts[PEG_COUNT_MAX] = { 0 };

bool Http2Module::begin(const char*, int, SnortConfig*)
{
    delete params;
    params = new Http2ParaList;
    return true;
}

bool Http2Module::set(const char*, Value& /*val*/, SnortConfig*)
{
    return false;
}

bool Http2Module::end(const char*, int, SnortConfig*)
{
    return true;
}

