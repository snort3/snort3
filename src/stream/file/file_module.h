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
// file_module.h author Russ Combs <rucombs@cisco.com>

#ifndef FILE_MODULE_H
#define FILE_MODULE_H

#include "framework/module.h"

namespace snort
{
struct SnortConfig;
}

extern const PegInfo file_pegs[];
extern THREAD_LOCAL struct FileStats file_stats;
extern THREAD_LOCAL snort::ProfileStats file_perf_stats;

//-------------------------------------------------------------------------
// stream_file module
//-------------------------------------------------------------------------

#define MOD_NAME "stream_file"
#define MOD_HELP "stream inspector for file flow tracking and processing"

class StreamFileModule : public snort::Module
{
public:
    StreamFileModule();

    bool begin(const char*, int, snort::SnortConfig*) override;
    bool set(const char*, snort::Value&, snort::SnortConfig*) override;

    Usage get_usage() const override
    { return INSPECT; }

public:
    bool upload;
};

#endif

