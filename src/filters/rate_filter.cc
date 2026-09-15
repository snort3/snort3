//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2009-2013 Sourcefire, Inc.
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

// rate_filter.cc author Dilbagh Chahal <dchahal@sourcefire.com>
// rate filter interface for Snort

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <atomic>
#include <utility>

#include "rate_filter.h"

#include "detection/detection_engine.h"
#include "detection/ips_context.h"
#include "detection/rules.h"
#include "detection/treenodes.h"
#include "flow/flow.h"
#include "hash/ghash.h"
#include "main/policy.h"
#include "main/snort_config.h"
#include "protocols/ip.h"
#include "protocols/layer.h"
#include "protocols/packet.h"
#include "time/packet_time.h"
#include "utils/util.h"

#include "sfrf.h"

using namespace snort;

static std::atomic<unsigned> rf_flow_data_id { 0 };

class RateFilterFlowData : public FlowData
{
public:
    RateFilterFlowData(unsigned id, SFRFGaugeKeys&& g) : FlowData(id), gauges(std::move(g)) { }
    ~RateFilterFlowData() override;

    FLOW_DATA_SIZE_OF_EXTRA(RateFilterFlowData,
        gauges.capacity() * sizeof(SFRFGaugeKey))

private:
    const SFRFGaugeKeys gauges;
};

RateFilterFlowData::~RateFilterFlowData()
{
    SFRF_ReleaseGauges(gauges);
}

static bool is_tunnel_carried(const Packet* p)
{
    if ( p->is_tunnel_encapsulated() || (p->proto_bits & PROTO_BIT__MPLS) )
        return true;

    ip::IpApi outer_ip;
    int8_t layer_index = 0;

    layer::set_outer_ip_api(p, outer_ip, layer_index);

    // Plain IP tunnels such as GRE do not set the decapsulation marker.  A
    // distinct outer IP layer still proves that this SYN arrived as a passenger.
    return outer_ip.is_valid() && outer_ip != p->ptrs.ip_api;
}

RateFilterConfig* RateFilter_ConfigNew()
{
    RateFilterConfig* rf_config = (RateFilterConfig*)snort_calloc(sizeof(*rf_config));
    rf_config->memcap = 16 * 1024 * 1024;
    return rf_config;
}

void RateFilter_ConfigFree(RateFilterConfig* config)
{
    int i;

    if (config == nullptr)
        return;

    for (i = 0; i < SFRF_MAX_GENID; i++)
    {
        if ( config->genHash[i] )
            delete config->genHash[i];
    }

    snort_free(config);
}

void RateFilter_Cleanup()
{
    SFRF_Delete();
}

/*
 * Create and Add a Thresholding Event Object
 */
int RateFilter_Create(
    SnortConfig* sc, RateFilterConfig* rf_config, tSFRFConfigNode* thdx)
{
    int error;

    if (rf_config == nullptr)
        return -1;

#ifdef RF_DBG
    printf(
        "THRESHOLD: gid=%u, sid=%u, tracking=%d, count=%u, seconds=%u \n",
        thdx->gid, thdx->sid, thdx->tracking, unsigned(thdx->count), thdx->seconds);
#endif

    /* Add the object to the table - */
    error = SFRF_ConfigAdd(sc, rf_config, thdx);

    // enable internal events as required
    if ( !error && EventIsInternal(thdx->gid) )
    {
        enable_internal_event(rf_config, thdx->sid);

        if ( thdx->sid == SESSION_EVENT_SETUP )
        {
            enable_internal_event(rf_config, SESSION_EVENT_CLEAR);

            if ( !thdx->seconds && !rf_flow_data_id.load(std::memory_order_relaxed) )
                rf_flow_data_id.store(FlowData::create_flow_data_id(), std::memory_order_relaxed);
        }
    }
    return error;
}

/*
    Test an event against the threshold object table
    to determine if the new_action should be applied.

    returns 1 - rate threshold reached
            0 - rate threshold not reached
*/
int RateFilter_Test(const OptTreeNode* otn, Packet* p)
{
    unsigned gid = otn->sigInfo.gid;
    unsigned sid = otn->sigInfo.sid;

    const SfIp* sip;
    const SfIp* dip;
    SfIp cleared;

    if ( p->has_ip_hdr() )
    {
        sip = p->ptrs.ip_api.get_src();
        dip = p->ptrs.ip_api.get_dst();
    }
    else
    {
        cleared.clear();
        sip = &cleared;
        dip = &cleared;
    }

    RateFilterConfig* rfc = p->context->conf->rate_filter_config;

    return SFRF_TestThreshold(rfc, gid, sid, get_inspection_policy()->policy_id,
        sip, dip, p->pkth->ts.tv_sec, SFRF_COUNT_INCREMENT);
}

int RateFilter_SessionEvent(unsigned sid, Flow& flow, const SnortConfig& sc)
{
    RateFilterConfig* rfc = sc.rate_filter_config;
    SFRFGaugeKeys gauges;
    bool tunnel_carried = false;

    if ( sid == SESSION_EVENT_SYN_RX )
    {
        const Packet* packet = DetectionEngine::get_current_packet();

        if ( packet && packet->flow == &flow && packet->has_ip_hdr() )
            tunnel_carried = is_tunnel_carried(packet);
    }

    const unsigned fd_id = rf_flow_data_id.load(std::memory_order_relaxed);

    if ( fd_id )
        gauges.reserve(2);

    const int action = SFRF_TestThreshold(rfc, GID_SESSION, sid,
        get_inspection_policy()->policy_id, &flow.client_ip, &flow.server_ip,
        packet_time(), SFRF_COUNT_INCREMENT, &gauges, tunnel_carried);

    if ( !gauges.empty() && fd_id )
        flow.set_flow_data(new RateFilterFlowData(fd_id, std::move(gauges)));

    return action;
}

void RateFilter_SessionRelease(Flow& flow)
{
    const unsigned fd_id = rf_flow_data_id.load(std::memory_order_relaxed);

    if ( !fd_id )
        return;

    flow.free_flow_data(fd_id);
}
