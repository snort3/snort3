//--------------------------------------------------------------------------
// Copyright (C) 2020-2020 Cisco and/or its affiliates. All rights reserved.
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

// payload_injector_module.cc author Maya Dagon <mdagon@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "payload_injector_module.h"

#include "detection/detection_engine.h"
#include "packet_io/active.h"
#include "protocols/packet.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

#define s_name "payload_injector"
#define s_help \
    "payload injection utility"

using namespace snort;

THREAD_LOCAL PayloadInjectorCounts payload_injector_stats;

const PegInfo payload_injector_pegs[] =
{
    { CountType::SUM, "http_injects", "total number of http injections" },
    { CountType::END, nullptr, nullptr }
};

bool PayloadInjectorModule::configured = false;

PayloadInjectorModule::PayloadInjectorModule() :
    Module(s_name, s_help)
{ }

const PegInfo* PayloadInjectorModule::get_pegs() const
{ return payload_injector_pegs; }

PegCount* PayloadInjectorModule::get_counts() const
{ return (PegCount*)&payload_injector_stats; }

bool PayloadInjectorModule::end(const char*, int, SnortConfig*)
{
    configured = true;
    return true;
}

InjectionReturnStatus PayloadInjectorModule::inject_http_payload(Packet* p, InjectionControl& control)
{
    InjectionReturnStatus status = INJECTION_SUCCESS;

    assert(p != nullptr);

    if (configured)
    {
        EncodeFlags df = (p->packet_flags & PKT_FROM_SERVER) ? ENC_FLAG_FWD : 0;
        df |= ENC_FLAG_RST_SRVR; // Send RST to server.

        if (p->packet_flags & PKT_STREAM_EST)
        {
            payload_injector_stats.http_injects++;
            p->active->send_data(p, df, control.http_page, control.http_page_len);
        }
        else
            status = ERR_STREAM_NOT_ESTABLISHED;
    }
    else
        status = ERR_INJECTOR_NOT_CONFIGURED;

    p->active->block_session(p, true);

    DetectionEngine::disable_all(p);

    if ( p->flow )
        p->flow->set_state(Flow::FlowState::BLOCK);

    return status;
}
