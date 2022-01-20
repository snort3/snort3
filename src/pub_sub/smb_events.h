//--------------------------------------------------------------------------
// Copyright (C) 2021-2022 Cisco and/or its affiliates. All rights reserved.
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
// smb_events.h author Sreeja Athirkandathil Narayanan <sathirka@cisco.com>

#ifndef SMB_EVENTS_H
#define SMB_EVENTS_H

#include "framework/data_bus.h"

#define FP_SMB_DATA_EVENT "fp_smb_data_event"

namespace snort
{

class FpSMBDataEvent : public snort::DataEvent
{
public:
    FpSMBDataEvent(const snort::Packet* p, unsigned major, unsigned minor,
        uint32_t flags) : pkt(p), major_version(major), minor_version(minor), flags(flags) { }

    const snort::Packet* get_packet() override
    { return pkt; }

    unsigned get_fp_smb_major() const
    { return major_version; }

    unsigned get_fp_smb_minor() const
    { return minor_version; }

    uint32_t get_fp_smb_flags() const
    { return flags; }

private:
    const snort::Packet* pkt;
    unsigned major_version;
    unsigned minor_version;
    uint32_t flags;
};

}

#endif // SMB_EVENTS_H
