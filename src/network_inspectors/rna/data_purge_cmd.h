//--------------------------------------------------------------------------
// Copyright (C) 2020-2022 Cisco and/or its affiliates. All rights reserved.
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

// data_purge_cmd.h author Silviu Minut <sminut@cisco.com>

#ifndef DATA_PURGE_CMD_H
#define DATA_PURGE_CMD_H

#include "main/analyzer_command.h"

#include "rna_mac_cache.h"

class DataPurgeAC : public snort::AnalyzerCommand
{
public:

    DataPurgeAC(HostCacheMac* new_cache) : mac_cache(new_cache) { }

    ~DataPurgeAC() override;

    bool execute(Analyzer&, void**) override;

    const char* stringify() override { return "DATA_PURGE"; }

private:
    HostCacheMac* mac_cache;
};

#endif
