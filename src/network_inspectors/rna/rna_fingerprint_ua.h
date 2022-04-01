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

// rna_fingerprint_ua.h author Masud Hasan <mashasan@cisco.com>

#ifndef RNA_FINGERPRINT_UA_H
#define RNA_FINGERPRINT_UA_H

#include "main/snort_types.h"
#include "search_engines/search_tool.h"

#include "rna_fingerprint.h"

#define MAX_USER_AGENT_DEVICES 16

namespace snort
{

class SO_PUBLIC UaFingerprint : public FpFingerprint
{
public:
    std::string user_agent;
    std::string host_name;
    std::string device;
    uint32_t part_num = 0;
    uint32_t total_parts = 0;

    bool operator==(const UaFingerprint& y) const;
};

class SO_PUBLIC UaFpProcessor
{
public:
    ~UaFpProcessor();

    bool has_pattern()
    { return os_mpse != nullptr; }

    void make_mpse(bool priority = false);

    void match_mpse(const char*, const char*, const UaFingerprint*&, const char*&, bool&);

    void push(const RawFingerprint&);

    void push_agent(const UaFingerprint& uafp)
    { os_fps.emplace_back(uafp); }

    void push_device(const UaFingerprint& uafp)
    { device_fps.emplace_back(uafp); }

    void push_jb(const UaFingerprint& uafp)
    { jb_fps.emplace_back(uafp); }

    void push_jb_host(const UaFingerprint& uafp)
    { jb_host_fps.emplace_back(uafp); }

private:
    std::vector<UaFingerprint> os_fps;
    std::vector<UaFingerprint> device_fps;
    std::vector<UaFingerprint> jb_fps;
    std::vector<UaFingerprint> jb_host_fps;

    snort::SearchTool* os_mpse = nullptr;
    snort::SearchTool* device_mpse = nullptr;
    snort::SearchTool* jb_mpse = nullptr;
    snort::SearchTool* jb_host_mpse = nullptr;
};

} // end of namespace snort

snort::UaFpProcessor* get_ua_fp_processor();
SO_PUBLIC void set_ua_fp_processor(snort::UaFpProcessor*);

#endif
