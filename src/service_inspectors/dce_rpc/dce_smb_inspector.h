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

// dce_smb_inspector.h author Dipta Pandit <dipandit@cisco.com>

#ifndef DCE_SMB_INSPECTOR_H
#define DCE_SMB_INSPECTOR_H

#include "managers/inspector_manager.h"

#include "dce_smb_module.h"
#include "dce_smb_paf.h"

class Dce2Smb : public snort::Inspector
{
public:
    Dce2Smb(const dce2SmbProtoConf&);
    ~Dce2Smb() override;

    bool configure(snort::SnortConfig*) override;
    void show(const snort::SnortConfig*) const override;
    void eval(snort::Packet*) override;
    void clear(snort::Packet*) override;

    snort::StreamSplitter* get_splitter(bool c2s) override
    { return new Dce2SmbSplitter(c2s); }

    bool can_carve_files() const override
    { return true; }

private:
    dce2SmbProtoConf config;
};

#endif

