//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// service_detector.h author Sourcefire Inc.

#ifndef SERVICE_DETECTOR_H
#define SERVICE_DETECTOR_H

#include "appid_detector.h"
#include "service_discovery.h"

#define APPID_EARLY_SESSION_FLAG_FW_RULE    1

class ServiceDetector : public AppIdDetector
{
public:
    ServiceDetector();
    void do_custom_init() override { }
    void release_thread_resources() override { }
    void register_appid(AppId, unsigned extractsInfo) override;
    int service_inprocess(AppIdSession&, const snort::Packet*, AppidSessionDirection dir);
    int add_service(AppIdSession&, const snort::Packet*, AppidSessionDirection dir, AppId, const char* vendor = nullptr,
        const char* version = nullptr, const snort::AppIdServiceSubtype* = nullptr);
    int add_service_consume_subtype(AppIdSession&, const snort::Packet*, AppidSessionDirection dir, AppId,
        const char* vendor, const char* version, snort::AppIdServiceSubtype*);
    int incompatible_data(AppIdSession&, const snort::Packet*, AppidSessionDirection dir);
    int fail_service(AppIdSession&, const snort::Packet*, AppidSessionDirection dir);

    void add_host_info(AppIdSession&, SERVICE_HOST_INFO_CODE, const void*)
    {
        // FIXIT-L - this function is called but does nothing... what if anything should it do...
    }

    void add_miscellaneous_info(AppIdSession& asd, AppId miscId)
    {
        asd.misc_app_id = miscId;
    }

    void initialize_expected_session(AppIdSession&, AppIdSession&, uint64_t flags, AppidSessionDirection dir);

private:
    int update_service_data(AppIdSession&, const snort::Packet*, AppidSessionDirection dir, AppId, const char* vendor,
        const char* version);
};
#endif

