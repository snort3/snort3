//--------------------------------------------------------------------------
// Copyright (C) 2019-2024 Cisco and/or its affiliates. All rights reserved.
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

// rna_inspector.cc author Masud Hasan <mashasan@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "rna_inspector.h"

#include <cassert>
#include <fstream>
#include <sstream>
#include <string>

#include "log/messages.h"
#include "main/snort.h"
#include "protocols/packet.h"
#include "pub_sub/appid_event_ids.h"
#include "pub_sub/dhcp_events.h"
#include "pub_sub/intrinsic_event_ids.h"
#include "pub_sub/rna_events.h"
#include "pub_sub/smb_events.h"
#include "pub_sub/stream_event_ids.h"

#include "rna_cpe_os.h"
#include "rna_event_handler.h"
#include "rna_fingerprint_smb.h"
#include "rna_fingerprint_tcp.h"
#include "rna_fingerprint_ua.h"
#include "rna_fingerprint_udp.h"
#include "rna_flow.h"
#include "rna_mac_cache.h"
#include "rna_module.h"
#include "rna_pnd.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;
using namespace std;

THREAD_LOCAL RnaStats rna_stats;
THREAD_LOCAL ProfileStats rna_perf_stats;

unsigned RnaConfig::pub_id = 0;

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

HostCacheMac* host_cache_mac_ptr = nullptr;

RnaInspector::RnaInspector(RnaModule* mod)
{
    mod_conf = mod->get_config();
    load_rna_conf();
    if ( mod_conf )
        pnd = new RnaPnd(mod_conf->enable_logger, mod_conf->rna_conf_path, rna_conf);
    else
        pnd = new RnaPnd(false, "", rna_conf);
}

RnaInspector::~RnaInspector()
{
    delete pnd;
    delete rna_conf;
    if (mod_conf)
    {
        delete mod_conf->tcp_processor;
        delete mod_conf->ua_processor;
        delete mod_conf->udp_processor;
        delete mod_conf->smb_processor;
        delete mod_conf;
    }
}

bool RnaInspector::configure(SnortConfig*)
{
    RnaConfig::pub_id = DataBus::get_id(rna_pub_key);

    DataBus::subscribe_network( appid_pub_key, AppIdEventIds::ANY_CHANGE, new RnaAppidEventHandler(*pnd) );
    DataBus::subscribe_network( appid_pub_key, AppIdEventIds::DHCP_INFO, new RnaDHCPInfoEventHandler(*pnd) );
    DataBus::subscribe_network( appid_pub_key, AppIdEventIds::DHCP_DATA, new RnaDHCPDataEventHandler(*pnd) );
    DataBus::subscribe_network( appid_pub_key, AppIdEventIds::FP_SMB_DATA, new RnaFpSMBEventHandler(*pnd) );

    DataBus::subscribe_network( stream_pub_key, StreamEventIds::ICMP_NEW_FLOW, new RnaIcmpNewFlowEventHandler(*pnd) );
    DataBus::subscribe_network( stream_pub_key, StreamEventIds::ICMP_BIDIRECTIONAL, new RnaIcmpBidirectionalEventHandler(*pnd) );

    DataBus::subscribe_network( stream_pub_key, StreamEventIds::IP_NEW_FLOW, new RnaIpNewFlowEventHandler(*pnd) );
    DataBus::subscribe_network( stream_pub_key, StreamEventIds::IP_BIDIRECTIONAL, new RnaIpBidirectionalEventHandler(*pnd) );

    DataBus::subscribe_network( stream_pub_key, StreamEventIds::UDP_NEW_FLOW, new RnaUdpNewFlowEventHandler(*pnd) );
    DataBus::subscribe_network( stream_pub_key, StreamEventIds::UDP_BIDIRECTIONAL, new RnaUdpBidirectionalEventHandler(*pnd) );

    DataBus::subscribe_network( stream_pub_key, StreamEventIds::TCP_SYN, new RnaTcpSynEventHandler(*pnd) );
    DataBus::subscribe_network( stream_pub_key, StreamEventIds::TCP_SYN_ACK, new RnaTcpSynAckEventHandler(*pnd) );
    DataBus::subscribe_network( stream_pub_key, StreamEventIds::TCP_MIDSTREAM, new RnaTcpMidstreamEventHandler(*pnd) );

    DataBus::subscribe_network( external_pub_key, ExternalEventIds::CPE_OS_INFO, new RnaCPEOSInfoEventHandler(*pnd) );
    DataBus::subscribe_network( netflow_pub_key, NetFlowEventIds::DATA, new RnaNetFlowEventHandler(*pnd) );

    if (rna_conf && rna_conf->log_when_idle)
        DataBus::subscribe_network(intrinsic_pub_key, IntrinsicEventIds::THREAD_IDLE, new RnaIdleEventHandler(*pnd) );

    if ( mod_conf->ua_processor )
        mod_conf->ua_processor->make_mpse();

    return true;
}

void RnaInspector::install_reload_handler(SnortConfig* sc)
{ sc->register_reload_handler(new FpProcReloadTuner(*mod_conf)); }

void RnaInspector::eval(Packet* p)
{
    // cppcheck-suppress unreadVariable
    Profile profile(rna_perf_stats);
    ++rna_stats.other_packets;
    update_rna_pkt_stats(p);

    assert( !p->flow );
    assert( !(BIT((unsigned)p->type()) & PROTO_BIT__ANY_SSN) );

    // Handling untracked sessions, e.g., non-IP packets
    pnd->analyze_flow_non_ip(p);
}

void RnaInspector::show(const SnortConfig*) const
{
    if ( mod_conf )
    {
        ConfigLogger::log_value("rna_conf_path", mod_conf->rna_conf_path.c_str());
        ConfigLogger::log_flag("enable_logger", mod_conf->enable_logger);
        ConfigLogger::log_flag("log_when_idle", mod_conf->log_when_idle);
    }

    if ( rna_conf )
    {
        ConfigLogger::log_value("UpdateTimeout", rna_conf->update_timeout);
        ConfigLogger::log_value("MaxHostClientApps", rna_conf->max_host_client_apps);
        ConfigLogger::log_value("MaxPayloads", rna_conf->max_payloads);
        ConfigLogger::log_value("MaxHostServices", rna_conf->max_host_services);
        ConfigLogger::log_value("MaxHostServiceInfo", rna_conf->max_host_service_info);
        ConfigLogger::log_value("BannerGrab", rna_conf->enable_banner_grab);
    }
}

void RnaInspector::tinit()
{
    // thread local initialization
    set_tcp_fp_processor(mod_conf->tcp_processor);
    set_ua_fp_processor(mod_conf->ua_processor);
    set_udp_fp_processor(mod_conf->udp_processor);
    set_smb_fp_processor(mod_conf->smb_processor);
    set_host_cache_mac(host_cache_mac_ptr);
}

void RnaInspector::tterm()
{
    // thread local cleanup
}

void RnaInspector::load_rna_conf()
{
    if (rna_conf)
        delete rna_conf;
    rna_conf = new RnaConfig; // initialize with defaults

    if (!mod_conf)
        return;

    ifstream in_stream(mod_conf->rna_conf_path);
    if (!in_stream)
        return;

    uint32_t line_num = 0;

    while (in_stream)
    {
        string line;
        getline(in_stream, line);
        ++line_num;
        if (line.empty() or line.front() == '#')
            continue;

        string config_type;
        string config_key;
        string config_value;
        istringstream line_stream(line);

        line_stream >> config_type >> config_key >> config_value;
        if (config_type.empty() or config_key.empty() or config_value.empty())
        {
            WarningMessage("RNA: Empty configuration items at line %u from %s\n",
                line_num, mod_conf->rna_conf_path.c_str());
            continue;
        }

        if (config_type == "pnd" and config_key == "UpdateTimeout")
            rna_conf->update_timeout = stoi(config_value);
        else if (config_type == "config" and config_key == "MaxHostClientApps")
            rna_conf->max_host_client_apps = stoi(config_value);
        else if (config_type == "config" and config_key == "MaxPayloads")
            rna_conf->max_payloads = stoi(config_value);
        else if (config_type == "config" and config_key == "MaxHostServices")
            rna_conf->max_host_services = stoi(config_value);
        else if (config_type == "config" and config_key == "MaxHostServiceInfo")
            rna_conf->max_host_service_info = stoi(config_value);
        else if (config_type == "protoid" and config_key == "BannerGrab" and config_value != "0")
            rna_conf->enable_banner_grab = true;
    }

    in_stream.close();
}

void RnaInspector::get_or_create_fp_processor(TcpFpProcessor*& tfp, UaFpProcessor*& uafp,
    UdpFpProcessor*& udpfp, SmbFpProcessor*& smbfp)
{
    if ( !mod_conf )
        return;

    if ( !mod_conf->tcp_processor )
        mod_conf->tcp_processor = new TcpFpProcessor;
    if ( !mod_conf->ua_processor )
        mod_conf->ua_processor = new UaFpProcessor;
    if ( !mod_conf->udp_processor )
        mod_conf->udp_processor = new UdpFpProcessor;
    if ( !mod_conf->smb_processor )
        mod_conf->smb_processor = new SmbFpProcessor;

    tfp = mod_conf->tcp_processor;
    uafp = mod_conf->ua_processor;
    udpfp = mod_conf->udp_processor;
    smbfp = mod_conf->smb_processor;
}

void RnaInspector::set_fp_processor(TcpFpProcessor* tfp, UaFpProcessor* uafp, UdpFpProcessor* udpfp,
    SmbFpProcessor* smbfp)
{
    if ( !mod_conf )
        return;

    delete mod_conf->tcp_processor;
    mod_conf->tcp_processor = tfp;

    delete mod_conf->ua_processor;
    mod_conf->ua_processor = uafp;

    delete mod_conf->udp_processor;
    mod_conf->udp_processor = udpfp;

    delete mod_conf->smb_processor;
    mod_conf->smb_processor = smbfp;
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* rna_mod_ctor()
{ return new RnaModule; }

static void rna_mod_dtor(Module* m)
{ delete m; }

static void rna_inspector_pinit()
{
    // global initialization
    RNAFlow::init();
    host_cache_mac_ptr = new HostCacheMac(MAC_CACHE_INITIAL_SIZE);
    set_host_cache_mac(host_cache_mac_ptr);
}

static void rna_inspector_pterm()
{
    // global cleanup
    delete host_cache_mac_ptr;
}

static Inspector* rna_inspector_ctor(Module* m)
{ return new RnaInspector((RnaModule*)m); }

static void rna_inspector_dtor(Inspector* p)
{ delete p; }

static const InspectApi rna_inspector_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        RNA_NAME,
        RNA_HELP,
        rna_mod_ctor,
        rna_mod_dtor
    },
    IT_CONTROL,
    PROTO_BIT__ETH,
    nullptr, // buffers
    nullptr, // service
    rna_inspector_pinit,
    rna_inspector_pterm,
    nullptr, // pre-config tinit
    nullptr, // pre-config tterm
    rna_inspector_ctor,
    rna_inspector_dtor,
    nullptr, // ssn
    nullptr  // reset
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* nin_rna[] =
#endif
{
    &rna_inspector_api.base,
    nullptr
};

#ifdef UNIT_TEST
TEST_CASE("RNA inspector", "[rna_inspector]")
{
    SECTION("inspector show")
    {
        RnaModule mod;
        RnaInspector ins(&mod);
        ins.show(nullptr);
    }

    SECTION("set and get processor")
    {
        RnaModule mod;
        mod.begin(RNA_NAME, 0, nullptr);
        RnaInspector ins(&mod);
        TcpFpProcessor* tfp = nullptr;
        UaFpProcessor* uafp = nullptr;
        UdpFpProcessor* udpfp = nullptr;
        SmbFpProcessor* smbfp = nullptr;
        ins.set_fp_processor(tfp, uafp, udpfp, smbfp);
        ins.get_or_create_fp_processor(tfp, uafp, udpfp, smbfp);
        CHECK(tfp != nullptr);
        CHECK(uafp != nullptr);
        CHECK(udpfp != nullptr);
        CHECK(smbfp != nullptr);
    }
}
#endif
