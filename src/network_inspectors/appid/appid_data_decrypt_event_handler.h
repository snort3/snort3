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

// appid_data_decrypt_event_handler.h author Sreeja Athirkandathil Narayanan <sathirka@cisco.com>

#ifndef APPID_DATA_DECRYPT_EVENT_HANDLER_H
#define APPID_DATA_DECRYPT_EVENT_HANDLER_H

#include "pub_sub/data_decrypt_event.h"

#include "appid_session.h"

class DataDecryptEventHandler : public snort::DataHandler
{
public:
    DataDecryptEventHandler() : DataHandler(MOD_NAME){ }

    void handle(snort::DataEvent& event, snort::Flow* flow) override
    {
        assert(flow);
        AppIdSession* asd = snort::appid_api.get_appid_session(*flow);
        if (!asd or
            !asd->get_session_flags(APPID_SESSION_DISCOVER_APP | APPID_SESSION_SPECIAL_MONITORED))
                return;
        const DataDecryptEvent& data_decrypt_event = static_cast<DataDecryptEvent&>(event);
        if (data_decrypt_event.get_type() == DataDecryptEvent::DATA_DECRYPT_MONITOR_EVENT)
        {
            asd->set_session_flags(APPID_SESSION_DECRYPT_MONITOR);
        }
    }
};

#endif

