//--------------------------------------------------------------------------
// Copyright (C) 2017-2017 Cisco and/or its affiliates. All rights reserved.
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

// appid_peg_counts.h author davis mcpherson <davmcphe@cisco.com>

#ifndef APPID_PEG_COUNTS_H
#define APPID_PEG_COUNTS_H

// The AppIdPegCounts class provides an API to manage the peg counts maintained by AppId.
// AppId defines peg counts that are known at compile time as well as a set of counts for
// each application that it can detect.  This list of applications is not known until the
// appMapping.data configuration file is loaded so methods are provided to dynamically
// initialize the PegInfo and PegCount array when that file is loaded.
// Functions for incrementing the peg counts are also provided.  The AppId can be a very large
// number so using it as the array index is not practical, therefore when the dynamic pegs are
// added we also initialize a std::map that is used to translate the AppId to its array index.

#include <map>
#include <vector>

#include "application_ids.h"
#include "framework/counts.h"
#include "main/thread.h"
#include "utils/util.h"

class AppInfoTableEntry;

class AppIdPegCounts
{
public:
    enum DiscoveryPegs
    {
        PACKETS = 0,
        PROCESSED_PACKETS,
        IGNORED_PACKETS,
        TOTAL_SESSIONS,
        NUM_APPID_GLOBAL_PEGS
    };

    enum DetectorPegs
    {
        SERVICE_DETECTS = 0,
        CLIENT_DETECTS,
        USER_DETECTS,
        PAYLOAD_DETECTS,
        MISC_DETECTS,
        NUM_APPID_DETECTOR_PEGS
    };

    AppIdPegCounts();
    ~AppIdPegCounts();

    static void add_app_peg_info(AppInfoTableEntry&, AppId);
    static PegCount* get_peg_counts();
    static PegInfo* get_peg_info();
    static void init_pegs();
    static void cleanup_pegs();
    static void cleanup_peg_info()
    {
        for ( auto& app_info : appid_detectors_peg_info )
        {
            snort_free((void*)app_info.name);
            snort_free((void*)app_info.help);
        }
    }

    static void inc_disco_peg(enum DiscoveryPegs stat)
     {
         (*appid_peg_counts)[stat]++;
     }

     static PegCount get_disco_peg(enum DiscoveryPegs stat)
     {
         return (*appid_peg_counts)[stat];
     }

     static void inc_service_count(AppId id)
     {
         if ( appid_detector_pegs_idx[id] )
             (*appid_peg_counts)[appid_detector_pegs_idx[id] + DetectorPegs::SERVICE_DETECTS]++;
     }

     static void inc_client_count(AppId id)
     {
         if ( appid_detector_pegs_idx[id] )
             (*appid_peg_counts)[appid_detector_pegs_idx[id] + DetectorPegs::CLIENT_DETECTS]++;
     }

     static void inc_user_count(AppId id)
     {
         if ( appid_detector_pegs_idx[id] )
             (*appid_peg_counts)[appid_detector_pegs_idx[id] + DetectorPegs::USER_DETECTS]++;
     }

     static void inc_payload_count(AppId id)
     {
         if ( appid_detector_pegs_idx[id] )
             (*appid_peg_counts)[appid_detector_pegs_idx[id] + DetectorPegs::PAYLOAD_DETECTS]++;
     }

     static void inc_misc_count(AppId id)
     {
         if ( appid_detector_pegs_idx[id] )
             (*appid_peg_counts)[appid_detector_pegs_idx[id] + DetectorPegs::MISC_DETECTS]++;
     }

     static void set_detectors_configured()
     {
         detectors_configured = true;
     }

private:
     static bool detectors_configured;
     static std::map<AppId, uint32_t> appid_detector_pegs_idx;
     static std::vector<PegInfo> appid_detectors_peg_info;
     static std::vector<PegInfo> appid_pegs;
     static THREAD_LOCAL std::vector<PegCount>* appid_peg_counts;

     static void init_detector_peg_info(std::string& app_name, std::string name_suffix,
         std::string help_suffix);
};
#endif
