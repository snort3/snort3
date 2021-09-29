//--------------------------------------------------------------------------
// Copyright (C) 2019-2021 Cisco and/or its affiliates. All rights reserved.
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
#include "managers/inspector_manager.h"
#include "protocols/packet.h"
#include "pub_sub/dhcp_events.h"
#include "pub_sub/smb_events.h"
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

bool RnaInspector::configure(SnortConfig* sc)
{
    DataBus::subscribe_global( APPID_EVENT_ANY_CHANGE, new RnaAppidEventHandler(*pnd), sc );
    DataBus::subscribe_global( DHCP_INFO_EVENT, new RnaDHCPInfoEventHandler(*pnd), sc);
    DataBus::subscribe_global( DHCP_DATA_EVENT, new RnaDHCPDataEventHandler(*pnd), sc);
    DataBus::subscribe_global( FP_SMB_DATA_EVENT, new RnaFpSMBEventHandler(*pnd), sc);

    DataBus::subscribe_global( STREAM_ICMP_NEW_FLOW_EVENT, new RnaIcmpNewFlowEventHandler(*pnd), sc );
    DataBus::subscribe_global( STREAM_ICMP_BIDIRECTIONAL_EVENT, new RnaIcmpBidirectionalEventHandler(*pnd), sc );

    DataBus::subscribe_global( STREAM_IP_NEW_FLOW_EVENT, new RnaIpNewFlowEventHandler(*pnd), sc );
    DataBus::subscribe_global( STREAM_IP_BIDIRECTIONAL_EVENT, new RnaIpBidirectionalEventHandler(*pnd), sc );

    DataBus::subscribe_global( STREAM_UDP_NEW_FLOW_EVENT, new RnaUdpNewFlowEventHandler(*pnd), sc );
    DataBus::subscribe_global( STREAM_UDP_BIDIRECTIONAL_EVENT, new RnaUdpBidirectionalEventHandler(*pnd), sc );

    DataBus::subscribe_global( STREAM_TCP_SYN_EVENT, new RnaTcpSynEventHandler(*pnd), sc );
    DataBus::subscribe_global( STREAM_TCP_SYN_ACK_EVENT, new RnaTcpSynAckEventHandler(*pnd), sc );
    DataBus::subscribe_global( STREAM_TCP_MIDSTREAM_EVENT, new RnaTcpMidstreamEventHandler(*pnd), sc );
    DataBus::subscribe_global( CPE_OS_INFO_EVENT, new RnaCPEOSInfoEventHandler(*pnd), sc );

    if (rna_conf && rna_conf->log_when_idle)
        DataBus::subscribe_global( THREAD_IDLE_EVENT, new RnaIdleEventHandler(*pnd), sc );

    // tinit is not called during reload, so pass processor pointers to threads via reload tuner
    if ( Snort::is_reloading() && InspectorManager::get_inspector(RNA_NAME, true) )
        sc->register_reload_resource_tuner(new FpProcReloadTuner(*mod_conf));

    return true;
}

void RnaInspector::eval(Packet* p)
{
    Profile profile(rna_perf_stats);
    ++rna_stats.other_packets;

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
