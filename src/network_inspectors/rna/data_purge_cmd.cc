//--------------------------------------------------------------------------
// Copyright (C) 2020-2020 Cisco and/or its affiliates. All rights reserved.
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

DataPurgeAC::~DataPurgeAC()
{
    auto rna_ins = (RnaInspector*) InspectorManager::get_inspector(RNA_NAME, true);
    RnaPnd* pnd = rna_ins->get_pnd();
    delete pnd->host_cache_mac_ptr;
    pnd->host_cache_mac_ptr = host_cache_mac;
    set_host_cache_mac(host_cache_mac);
}

bool DataPurgeAC::execute(Analyzer&, void**)
{
    set_host_cache_mac(host_cache_mac);
    return true;
}

