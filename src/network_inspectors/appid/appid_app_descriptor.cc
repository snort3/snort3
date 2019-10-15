//--------------------------------------------------------------------------
// Copyright (C) 2019-2019 Cisco and/or its affiliates. All rights reserved.
//--------------------------------------------------------------------------

// appid_app_descriptor.cc author Shravan Rangaraju <shrarang@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appid_app_descriptor.h"
#include "lua_detector_api.h"

using namespace snort;

void ApplicationDescriptor::set_id(const Packet& p, AppIdSession& asd,
    AppidSessionDirection dir, AppId app_id, AppidChangeBits& change_bits)
{
    if ( my_id != app_id )
    {
        set_id(app_id);
        check_detector_callback(p, asd, dir, app_id, change_bits);
    }
}

