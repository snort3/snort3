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

// appid_efp_process_event_handler.cc author Cliff Judge <cljudge@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appid_efp_process_event_handler.h"

#include "appid_debug.h"
#include "appid_inspector.h"
#include "appid_session.h"

using namespace snort;

void AppIdEfpProcessEventHandler::handle(DataEvent& event, Flow* flow)
{
    assert(flow);
    AppIdSession* asd = appid_api.get_appid_session(*flow);
    if (!asd or
        !asd->get_session_flags(APPID_SESSION_DISCOVER_APP | APPID_SESSION_SPECIAL_MONITORED))
        return;

    if (!pkt_thread_odp_ctxt or
        (pkt_thread_odp_ctxt->get_version() != asd->get_odp_ctxt_version()))
        return;

    const EfpProcessEvent &efp_process_event = static_cast<EfpProcessEvent&>(event);

    const std::string& name = efp_process_event.get_process_name();
    uint8_t conf = efp_process_event.get_process_confidence();

    AppId app_id = asd->get_odp_ctxt().get_efp_ca_matchers().match_efp_ca_pattern(name,
        conf);

    if (appidDebug->is_active())
        LogMessage("AppIdDbg %s encrypted client app %d process name '%s', "
            "confidence: %d\n", appidDebug->get_debug_session(), app_id, name.c_str(), conf);

    asd->set_efp_client_app_id(app_id);
}

