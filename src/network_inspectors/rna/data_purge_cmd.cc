//--------------------------------------------------------------------------
// Copyright (C) 2020-2023 Cisco and/or its affiliates. All rights reserved.
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

// data_purge_cmd.cc author Silviu Minut <sminut@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "data_purge_cmd.h"

#include "managers/inspector_manager.h"

#include "rna_inspector.h"
#include "rna_name.h"
#include "rna_pnd.h"

using namespace snort;

extern HostCacheMac* host_cache_mac_ptr;

DataPurgeAC::~DataPurgeAC()
{
    delete host_cache_mac_ptr;
    host_cache_mac_ptr = mac_cache;
    set_host_cache_mac(mac_cache);
}

bool DataPurgeAC::execute(Analyzer&, void**)
{
    set_host_cache_mac(mac_cache);
    return true;
}
