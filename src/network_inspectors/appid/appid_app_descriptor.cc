//--------------------------------------------------------------------------
// Copyright (C) 2019-2025 Cisco and/or its affiliates. All rights reserved.
//--------------------------------------------------------------------------

// appid_app_descriptor.cc author Shravan Rangaraju <shrarang@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appid_app_descriptor.h"
#include "app_info_table.h"
#include "appid_config.h"
#include "appid_module.h"
#include "appid_peg_counts.h"
#include "appid_types.h"
#include "lua_detector_api.h"

using namespace snort;

void ApplicationDescriptor::set_id(AppId app_id)
{
    my_id = app_id;
}

void ApplicationDescriptor::set_id(const Packet& p, AppIdSession& asd,
    AppidSessionDirection dir, AppId app_id, AppidChangeBits& change_bits)
{
    if ( my_id != app_id )
    {
        set_id(app_id);
        check_detector_callback(p, asd, dir, app_id, change_bits);
    }
}

void ServiceAppDescriptor::set_port_service_id(AppId id)
{
    if ( id != port_service_id )
        port_service_id = id;
}

void ServiceAppDescriptor::set_id(AppId app_id, OdpContext& odp_ctxt)
{
    if (get_id() != app_id)
    {
        ApplicationDescriptor::set_id(app_id);
        deferred = odp_ctxt.get_app_info_mgr().get_app_info_flags(app_id, APPINFO_FLAG_DEFER);
    }
}

void ClientAppDescriptor::update_user(AppId app_id, const char* username, AppidChangeBits& change_bits)
{
    if ( my_username != username )
    {
        my_username = username;
        change_bits.set(APPID_USER_INFO_BIT);
    }

    if ( my_user_id != app_id )
    {
        my_user_id = app_id;
        if ( app_id > APP_ID_NONE )
        {
            AppIdPegCounts::inc_user_count(app_id);
            change_bits.set(APPID_USER_INFO_BIT);
        }
    }
}
