//--------------------------------------------------------------------------
// Copyright (C) 2023-2024 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License Version 2 as
// published by the Free Software Foundation.  You may not use, modify or
// distribute this program under any other version of the GNU General
// Public License.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
// --------------------------------------------------------------------------------
// appid_cip_event_handler.h author Suriya Balu <subalu@cisco.com>

#ifndef APPID_CIP_EVENT_HANDLER_H
#define APPID_CIP_EVENT_HANDLER_H

#include "pub_sub/cip_events.h"
#include "appid_detector.h"
#include "appid_inspector.h"

class CipEventHandler : public snort::DataHandler
{
public:
    CipEventHandler(AppIdInspector& inspector) :
        DataHandler(MOD_NAME), inspector(inspector)
    { }

    void handle(snort::DataEvent&, snort::Flow*) override;

private:
    void client_handler(AppIdSession&);
    void service_handler(const snort::Packet&, AppIdSession&);

    AppIdInspector& inspector;
};

#endif //APPID_CIP_EVENT_HANDLER_H
