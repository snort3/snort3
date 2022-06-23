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

// rna_fingerprint_ua.cc author Masud Hasan <mashasan@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "rna_fingerprint_ua.h"

#include <algorithm>
#include <cstring>

#include "main/thread.h"

using namespace snort;
using namespace std;

static THREAD_LOCAL UaFpProcessor* ua_fp_processor = nullptr;

UaFpProcessor* get_ua_fp_processor()
{
    return ua_fp_processor;
}

void set_ua_fp_processor(UaFpProcessor* processor)
{
    ua_fp_processor = processor;
}

bool UaFingerprint::operator==(const UaFingerprint& y) const
{
    return fpid == y.fpid and part_num == y.part_num and total_parts == y.total_parts;
}

UaFpProcessor::~UaFpProcessor()
{
    delete os_mpse;
    delete device_mpse;
    delete jb_mpse;
    delete jb_host_mpse;
}

void UaFpProcessor::push(const RawFingerprint& rfp)
{
    if ( rfp.ua_type == JAIL_BROKEN_HOST )
    {
        if ( rfp.host_name.empty() )
            return;
        UaFingerprint uafp;
        uafp.fpid = rfp.fpid;
        uafp.fpuuid = rfp.fpuuid;
        uafp.fp_type = FpFingerprint::FpType::FP_TYPE_MOBILE;
        uafp.host_name = rfp.host_name;
        uafp.part_num = 0;
        uafp.total_parts = 1;
        push_jb_host(uafp);
    }
    else
    {
        for (size_t i = 0; i < rfp.user_agent.size(); ++i)
        {
            UaFingerprint uafp;
            uafp.fpid = rfp.fpid;
            uafp.fpuuid = rfp.fpuuid;
            uafp.user_agent = rfp.user_agent[i];
            uafp.part_num = i;
            uafp.total_parts = rfp.user_agent.size();
            if ( rfp.ua_type == OS_INFO )
            {
                uafp.fp_type = FpFingerprint::FpType::FP_TYPE_USERAGENT;
                push_agent(uafp);
            }
            else if ( rfp.ua_type == DEVICE_INFO )
            {
                uafp.device = rfp.device;
                uafp.fp_type = FpFingerprint::FpType::FP_TYPE_MOBILE;
                push_device(uafp);
            }
            else
            {
                uafp.fp_type = FpFingerprint::FpType::FP_TYPE_MOBILE;
                push_jb(uafp);
            }
        }
    }
}

void UaFpProcessor::make_mpse(bool priority)
{
    if ( priority )
    {
        delete os_mpse;
        delete device_mpse;
        delete jb_mpse;
        delete jb_host_mpse;

        os_mpse = device_mpse = jb_mpse = jb_host_mpse = nullptr;
    }

    if ( !os_mpse and !os_fps.empty() )
    {
        os_mpse = new SearchTool;
        for (auto& fp : os_fps)
            os_mpse->add(fp.user_agent.c_str(), fp.user_agent.size(), &fp);
        os_mpse->prep();
    }

    if ( !device_mpse and !device_fps.empty() )
    {
        device_mpse = new SearchTool;
        for (auto& fp : device_fps)
            device_mpse->add(fp.user_agent.c_str(), fp.user_agent.size(), &fp);
        device_mpse->prep();
    }

    if ( !jb_mpse and !jb_fps.empty() )
    {
        jb_mpse = new SearchTool;
        for (auto& fp : jb_fps)
            jb_mpse->add(fp.user_agent.c_str(), fp.user_agent.size(), &fp);
        jb_mpse->prep();
    }

    if ( !jb_host_mpse and !jb_host_fps.empty() )
    {
        jb_host_mpse = new SearchTool;
        for (auto& fp : jb_host_fps)
            jb_host_mpse->add(fp.host_name.c_str(), fp.host_name.size(), &fp);
        jb_host_mpse->prep();
    }
}

static int match_ua_part(void* id, void*, int, void* data, void*)
{
    auto cur_fp = (UaFingerprint*) id;
    auto matched_parts = (vector<UaFingerprint*>*)data;

    for (const auto& fp : *matched_parts)
        if ( *fp == *cur_fp )
            return 0; // ignore already recorded matching part

    matched_parts->emplace_back(cur_fp);
    return 0; // search continues for the next match
}

struct CompareParts
{
    bool operator()(const UaFingerprint* p1, const UaFingerprint* p2) const
    {
        return (p1->fpid < p2->fpid) or (p1->fpid == p2->fpid and p1->part_num < p2->part_num);
    }
};

static inline UaFingerprint* search_ua_fp(SearchTool* mpse, const char* start, unsigned len)
{
    if ( !mpse )
        return nullptr;

    vector<UaFingerprint*> matched_parts;
    mpse->find_all(start, len, match_ua_part, false, (void*)&matched_parts);
    if ( matched_parts.empty() )
        return nullptr;

    sort(matched_parts.begin(), matched_parts.end(), CompareParts());

    UaFingerprint* matched_fp = nullptr;
    uint32_t cur_fpid = 0, part_num = 0;
    for (auto& fp : matched_parts)
    {
        if ( cur_fpid != fp->fpid )
        {
            cur_fpid = fp->fpid;
            part_num = 0;
        }

        if ( part_num == fp->part_num )
        {
            if ( ++part_num == fp->total_parts and
                ( !matched_fp or matched_fp->user_agent.size() < fp->user_agent.size() ) )
                    matched_fp = fp;
        }
    }
    return matched_fp;
}

void UaFpProcessor::match_mpse(const char* host, const char* uagent, const UaFingerprint*& osfp,
    const char*& device_info, bool& jail_broken)
{
    unsigned len = strlen(uagent);
    osfp = search_ua_fp(os_mpse, uagent, len);
    if ( !osfp )
        return;

    auto devicefp = search_ua_fp(device_mpse, uagent, len);
    if ( devicefp )
        device_info = devicefp->device.c_str();

    auto jbfp = search_ua_fp(jb_mpse, uagent, len);
    if ( jbfp and search_ua_fp(jb_host_mpse, host, strlen(host)) )
        jail_broken = true;
}
