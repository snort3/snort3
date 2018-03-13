//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

// appid_http_event_handler.h author Steve Chew <stechew@cisco.com>

// Receive events from the HTTP inspector containing header information
// to be used to detect AppIds.

#ifndef APPID_HTTP_EVENT_HANDLER_H
#define APPID_HTTP_EVENT_HANDLER_H

#include "pub_sub/http_events.h"

namespace snort
{
class Flow;
}

class HttpEventHandler : public snort::DataHandler
{
public:
    enum HttpEventType
    {
        REQUEST_EVENT,
        RESPONSE_EVENT,
    };

    HttpEventHandler(HttpEventType type)
    {
        event_type = type;
    }

    void handle(snort::DataEvent&, snort::Flow*) override;

private:
    HttpEventType event_type;
};

#endif

