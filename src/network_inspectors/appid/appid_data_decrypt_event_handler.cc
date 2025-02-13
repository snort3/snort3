//--------------------------------------------------------------------------
// Copyright (C) 2023-2025 Cisco and/or its affiliates. All rights reserved.
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

// appid_data_decrypt_event_handler.cc author Shibin <shikv@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appid_data_decrypt_event_handler.h"

#include "detection/detection_engine.h"
#include "log/messages.h"
#include "pub_sub/data_decrypt_event.h"

#include "app_info_table.h"
#include "appid_debug.h"
#include "appid_discovery.h"
#include "appid_http_session.h"
#include "appid_inspector.h"
#include "appid_session.h"
#include "appid_session_api.h"

using namespace snort;

void DataDecryptEventHandler::handle(snort::DataEvent& event, snort::Flow* flow)
{
    assert(flow);
    AppIdSession* asd = snort::appid_api.get_appid_session(*flow);
    if (!asd)
    {
        Packet* p = DetectionEngine::get_current_packet();
        auto direction = p->is_from_client() ? APP_ID_FROM_INITIATOR : APP_ID_FROM_RESPONDER;
        asd = AppIdSession::allocate_session( p, p->get_ip_proto_next(), direction,
                inspector, *pkt_thread_odp_ctxt );
        if (appidDebug->is_enabled())
        {
            appidDebug->activate(flow, asd, inspector.get_ctxt().config.log_all_sessions);
            if (appidDebug->is_active())
                LogMessage("AppIdDbg %s New AppId session at Decryption event\n",
                        appidDebug->get_debug_session());
        }
    }

    if (!asd->get_session_flags(APPID_SESSION_DISCOVER_APP | APPID_SESSION_SPECIAL_MONITORED))
        return;

    const DataDecryptEvent& data_decrypt_event = static_cast<DataDecryptEvent&>(event);
    DataDecryptEvent::StateEventType state = data_decrypt_event.get_type();
    if (DataDecryptEvent::DATA_DECRYPT_MONITOR_EVENT == state)
        asd->set_session_flags(APPID_SESSION_DECRYPT_MONITOR);
    // Set a do not decrypt flag, so that an event can be generated after appid processes the packet
    else if (DataDecryptEvent::DATA_DECRYPT_DO_NOT_DECRYPT_EVENT == state)
        asd->set_session_flags(APPID_SESSION_DO_NOT_DECRYPT);
}

