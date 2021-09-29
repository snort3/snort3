//--------------------------------------------------------------------------
// Copyright (C) 2021-2021 Cisco and/or its affiliates. All rights reserved.
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

// rna_cpe_os.h author Arun Prasad Mandava <armandav@cisco.com>

#ifndef RNA_CPE_OS_H
#define RNA_CPE_OS_H

#define CPE_OS_INFO_EVENT "cpe_os_info_event"

class SO_PUBLIC CpeOsInfoEvent : public snort::DataEvent
{
public:
    CpeOsInfoEvent(const snort::Packet& p) : p(p) { }

    const snort::Packet* get_packet() override
    {
         return &p;
    }

    void add_os(const char *name)
    {
        hash ^= std::hash<std::string>{}(name);
        os_names.emplace_back(name);
    }

    uint32_t get_hash()
    {
        return hash;
    }

    const std::vector<const char*>* get_os_names()
    {
        return &os_names;
    }
private:
    const snort::Packet& p;
    std::vector<const char*> os_names;
    uint32_t hash = 0;
};

#endif
