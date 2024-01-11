//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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

class ServiceDetector : public AppIdDetector
{
public:
    ServiceDetector();

    void register_appid(AppId, unsigned extractsInfo, OdpContext& odp_ctxt) override;

    int service_inprocess(AppIdSession&, const snort::Packet*, AppidSessionDirection dir);

    int add_service(AppidChangeBits&, AppIdSession&, const snort::Packet*,
        AppidSessionDirection, AppId, const char* vendor = nullptr,
        const char* version = nullptr, AppIdServiceSubtype* = nullptr);

    int add_service_consume_subtype(AppIdSession&, const snort::Packet*,
        AppidSessionDirection dir, AppId, const char* vendor, const char* version,
        AppIdServiceSubtype*, AppidChangeBits&);

    int incompatible_data(AppIdSession&, const snort::Packet*, AppidSessionDirection dir);
    int fail_service(AppIdSession&, const snort::Packet*, AppidSessionDirection dir);

    void add_miscellaneous_info(AppIdSession& asd, AppId miscId)
    {
        asd.misc_app_id = miscId;
    }

private:
    int update_service_data(AppIdSession&, const snort::Packet*, AppidSessionDirection, AppId,
        const char*, const char*, AppidChangeBits&, AppIdServiceSubtype*);
};
#endif

