//--------------------------------------------------------------------------
// Copyright (C) 2016-2025 Cisco and/or its affiliates. All rights reserved.
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

// packet_capture.cc author Carter Waxman <cwaxman@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "packet_capture.h"

#include <pcap.h>

#include "framework/inspector.h"
#include "log/messages.h"
#include "main/thread_config.h"
#include "packet_io/sfdaq.h"
#include "protocols/packet.h"
#include "utils/util.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

#include "capture_module.h"

using namespace snort;
using namespace std;

#define FILE_NAME "packet_capture.pcap"
#define SNAP_LEN 65535

// -----------------------------------------------------------------------------
// static variables
// -----------------------------------------------------------------------------

static CaptureConfig config;

static THREAD_LOCAL pcap_t* pcap = nullptr;
static THREAD_LOCAL pcap_dumper_t* dumper = nullptr;
static THREAD_LOCAL struct bpf_program bpf;
static THREAD_LOCAL unsigned packet_count = 0;

// -----------------------------------------------------------------------------
// static functions
// -----------------------------------------------------------------------------

static inline bool capture_initialized()
{ return dumper != nullptr; }

static void _capture_term()
{
    if ( dumper )
    {
        pcap_dump_close(dumper);
        dumper = nullptr;
    }
    if ( pcap )
    {
        free(pcap);
        pcap = nullptr;
    }
    pcap_freecode(&bpf);
}

static int get_dlt()
{
    int dlt = SFDAQ::get_base_protocol();
    if (dlt == DLT_USER1)
        return DLT_EN10MB;
    return dlt;
}

static int _pcap_compile_nopcap(int snaplen_arg, int linktype_arg,
		    struct bpf_program *program,
		    const char *buf, int optimize, bpf_u_int32 mask)
{
	pcap_t *p;
	int ret;

	p = pcap_open_dead(linktype_arg, snaplen_arg);
	if (p == NULL)
		return (PCAP_ERROR);
	ret = pcap_compile(p, program, buf, optimize, mask);
	pcap_close(p);
	return (ret);
}

static bool bpf_compile_and_validate()
{
    // FIXIT-M This BPF compilation is not thread-safe and should be handled by the main thread
    if ( _pcap_compile_nopcap(SNAP_LEN, get_dlt(), &bpf,
        config.filter.c_str(), 1, 0) >= 0 )
    {
        if (bpf_validate(bpf.bf_insns, bpf.bf_len))
            return true;
        else
            WarningMessage("Unable to validate BPF filter\n");
    }
    else
        WarningMessage("Unable to compile BPF filter\n");
    return false;
}

static bool open_pcap_dumper()
{
    string fname;
    if ( config.capture_path.empty() ) 
        get_instance_file(fname, FILE_NAME);
    else
    {
        auto file_name = std::string(FILE_NAME);
        if ( ThreadConfig::get_instance_max() > 1 )
            file_name.insert(file_name.find(".pcap"), 
                            ("_" + std::to_string(get_instance_id()) + \
                             "_" + std::to_string(get_relative_instance_number())));
        fname = config.capture_path + "/" + file_name;
    }

    pcap = pcap_open_dead(get_dlt(), SNAP_LEN);
    dumper = pcap ? pcap_dump_open(pcap, fname.c_str()) : nullptr;

    if (dumper)
        return true;
    else
        WarningMessage("Could not initialize dump file\n");

    return false;
}

// for unit test
static void _packet_capture_enable(const string& f, const int16_t g = -1, const string& t = "", 
                                   const bool ci = true, const string& path = "", const unsigned max = 0)
{
    if ( !config.enabled )
    {
        config.filter = f;
        config.enabled = true;
        config.group = g;
        config.check_inner_pkt = ci;
        str_to_int_vector(t, ',', config.tenants);
        config.capture_path = path;
        config.max_packet_count = max;
    }
}

// for unit test
static void _packet_capture_disable()
{
    config.enabled = false;
    config.group = -1;
    config.tenants.clear();
    config.check_inner_pkt = true;
    config.capture_path.clear();
    config.max_packet_count = 0;
    LogMessage("Packet capture disabled\n");
}

// -----------------------------------------------------------------------------
// non-static functions
// -----------------------------------------------------------------------------

void packet_capture_enable(const string& f, const int16_t g, const string& t, const bool ci, 
                           const string& p, const unsigned max)
{

    _packet_capture_enable(f, g, t, ci, p, max);

    if ( !capture_initialized() )
    {
        if (bpf_compile_and_validate())
        {
            if (open_pcap_dumper())
            {
                LogMessage("Packet capture enabled\n");
                return;
            }
        }
        else
        {
            WarningMessage("Failed to enable Packet capture\n");
            packet_capture_disable();
        }
    }
}

void packet_capture_disable()
{
    _packet_capture_disable();
    if ( capture_initialized() )
        _capture_term();
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class PacketCapture : public Inspector
{
public:
    PacketCapture(CaptureModule*);

    // non-static functions
    void show(const SnortConfig*) const override;
    void eval(Packet*) override;
    void tterm() override { capture_term(); }

protected:
    virtual bool capture_init();
    virtual void capture_term();
    virtual void write_packet(Packet* p);
};

PacketCapture::PacketCapture(CaptureModule* m)
{ m->get_config(config); }

void PacketCapture::capture_term() { _capture_term(); }

bool PacketCapture::capture_init()
{
    if (bpf_compile_and_validate())
    {
        if (open_pcap_dumper())
        {
            LogMessage("Packet capture enabled\n");
            return true;
        }
    }
    packet_capture_disable();
    return false;
}

void PacketCapture::show(const SnortConfig*) const
{
    ConfigLogger::log_flag("enable", config.enabled);
    if (config.enabled) 
    {
        ConfigLogger::log_value("filter", config.filter.c_str());
        ConfigLogger::log_value("tenants", int_vector_to_str(config.tenants).c_str());
        ConfigLogger::log_value("capture_path", config.capture_path.c_str());
        ConfigLogger::log_value("max_packet_count", config.max_packet_count);
    }
}

void PacketCapture::eval(Packet* p)
{

    if ( config.enabled )
    {
        if ( (config.group != -1) and
            !((config.group == p->pkth->ingress_group) or
            (config.group == p->pkth->egress_group)) )
            return;

        if ( !capture_initialized() )
            if ( !capture_init() )
                return;

        if ( p->is_cooked() )
            return;

        if (!config.tenants.empty())
        {
            if (!std::any_of(config.tenants.begin(), config.tenants.end(),[&p](uint32_t tenant_id){
            return p->pkth->tenant_id == tenant_id;
            }))
            {
                cap_count_stats.checked++;
                return;
            }
        }

        bool matched_filter = false;
        if (!bpf.bf_insns)
        {
            matched_filter = true;
        }
        else
        {
            const uint8_t* filter_pkt = p->pkt;
            uint32_t filter_pkt_len = p->pktlen;
            uint32_t filter_pkth_len = p->pkth->pktlen;
            if (config.check_inner_pkt)
            {
                uint16_t inner_offset = p->get_inner_pkt_offset();
                if (inner_offset > 0 && inner_offset < filter_pkt_len && inner_offset < filter_pkth_len)
                {
                    filter_pkt += inner_offset;
                    filter_pkt_len -= inner_offset;
                    filter_pkth_len -= inner_offset;
                }
            }
            matched_filter = bpf_filter(bpf.bf_insns, filter_pkt, filter_pkt_len, filter_pkth_len);
        }

        if (matched_filter)
        {
            write_packet(p);
            cap_count_stats.matched++;
        }

        cap_count_stats.checked++;
    }
    else if ( capture_initialized() )
        capture_term();
}

void PacketCapture::write_packet(Packet* p)
{
    if ( config.max_packet_count )
    {
        if ( packet_count >= config.max_packet_count )
            return;

        packet_count++;
    }
    struct pcap_pkthdr pcaphdr;
    pcaphdr.ts = p->pkth->ts;
    pcaphdr.caplen = p->pktlen;
    pcaphdr.len = p->pkth->pktlen;
    pcap_dump((unsigned char*)dumper, &pcaphdr, p->pkt);
    pcap_dump_flush(dumper);
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new CaptureModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* pc_ctor(Module* m)
{ return new PacketCapture((CaptureModule*)m); }

static void pc_dtor(Inspector* p)
{ delete p; }

static const InspectApi pc_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CAPTURE_NAME,
        CAPTURE_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_PROBE_FIRST,
    PROTO_BIT__ANY_IP | PROTO_BIT__ETH,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    pc_ctor,
    pc_dtor,
    nullptr, // ssn
    nullptr  // reset
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* nin_packet_capture[] =
#endif
{
    &pc_api.base,
    nullptr
};

// --------------------------------------------------------------------------
// unit tests
// --------------------------------------------------------------------------

#ifdef UNIT_TEST

static bool bpf_compile_and_validate_test()
{
    if (_pcap_compile_nopcap(SNAP_LEN, DLT_EN10MB, &bpf,
        config.filter.c_str(), 1, 0) >= 0)
    {
        if (bpf_validate(bpf.bf_insns, bpf.bf_len))
            return true;
        else
            WarningMessage("Unable to validate BPF filter\n");
    }
    else
        WarningMessage("Unable to compile BPF filter\n");
    return false;
}

static Packet* init_null_packet()
{
    static Packet p(false);
    static DAQ_PktHdr_t h;

    p.pkth = &h;
    p.pkt = nullptr;
    p.pktlen = 0;
    h.pktlen = 0;

    return &p;
}

static Packet* init_packet_with_tenant(uint32_t tenant_id)
{
    static Packet p(false);
    static DAQ_PktHdr_t h;

    h.tenant_id = tenant_id;

    p.pkth = &h;
    p.pkt = nullptr;
    p.pktlen = 0;
    h.pktlen = 0;

    return &p;
}

class MockPacketCapture : public PacketCapture
{
public:
    bool write_packet_called = false;
    vector<Packet*> pcap;

    MockPacketCapture(CaptureModule* m) : PacketCapture(m) {}

protected:
    void write_packet(Packet* p) override
    {
        pcap.emplace_back(p);
        write_packet_called = true;
    }

    bool capture_init() override
    {
        if (bpf_compile_and_validate_test())
        {
            dumper = (pcap_dumper_t*)1;
            return true;
        }
        _packet_capture_disable();
        capture_term();
        return false;
    }

    void capture_term() override
    {
        dumper = nullptr;
        PacketCapture::capture_term();
    }
};


TEST_CASE("toggle", "[PacketCapture]")
{
    auto null_packet = init_null_packet();

    CaptureModule mod;
    MockPacketCapture cap(&mod);

    cap.write_packet_called = false;
    cap.eval(null_packet);
    CHECK ( !cap.write_packet_called );

    cap.write_packet_called = false;
    _packet_capture_enable("");
    cap.eval(null_packet);
    CHECK ( cap.write_packet_called );

    cap.write_packet_called = false;
    _packet_capture_disable();
    cap.eval(null_packet);
    CHECK ( !cap.write_packet_called );
}

TEST_CASE("lazy init", "[PacketCapture]")
{
    auto null_packet = init_null_packet();

    auto mod = (CaptureModule*)mod_ctor();
    auto real_cap = (PacketCapture*)pc_ctor(mod);

    CHECK ( (capture_initialized() == false) );

    real_cap->eval(null_packet);
    CHECK ( (capture_initialized() == false) );

    pc_dtor(real_cap);
    MockPacketCapture cap(mod);

    _packet_capture_enable("");
    CHECK ( (capture_initialized() == false) );

    cap.eval(null_packet);
    CHECK ( (capture_initialized() == true) );

    _packet_capture_disable();
    CHECK ( (capture_initialized() == true) );

    cap.eval(null_packet);
    CHECK ( (capture_initialized() == false) );

    mod_dtor(mod);
}

TEST_CASE("filter tenants", "[PacketCapture]")
{
    auto mod = (CaptureModule*)mod_ctor();
    auto real_cap = (PacketCapture*)pc_ctor(mod);

    CHECK ( (capture_initialized() == false) );

    pc_dtor(real_cap);
    MockPacketCapture cap(mod);

    _packet_capture_enable("",-1,"11,13");
    CHECK ( (capture_initialized() == false) );

    auto packet_tenants_11 = init_packet_with_tenant(11);
    cap.write_packet_called = false;
    cap.eval(packet_tenants_11);
    CHECK ( cap.write_packet_called );

    auto packet_tenants_13 = init_packet_with_tenant(13);
    cap.write_packet_called = false;
    cap.eval(packet_tenants_13);
    CHECK ( cap.write_packet_called );

    auto packet_tenants_22 = init_packet_with_tenant(22);
    cap.write_packet_called = false;
    cap.eval(packet_tenants_22);
    CHECK ( !cap.write_packet_called );

    _packet_capture_disable();
    mod_dtor(mod);
}

TEST_CASE("blank filter", "[PacketCapture]")
{
    auto null_packet = init_null_packet();

    const uint8_t cooked[] = "AbCdEfGhIjKlMnOpQrStUvWxYz";

    Packet p(false);
    DAQ_PktHdr_t daq_hdr;
    p.pkth = &daq_hdr;
    p.pkt = cooked;
    p.pktlen = sizeof(cooked);

    daq_hdr.pktlen = sizeof(cooked);

    CaptureModule mod;
    MockPacketCapture cap(&mod);

    _packet_capture_enable("");
    cap.eval(&p);

    REQUIRE ( cap.pcap.size() );
    CHECK ( cap.pcap[0] == &p );

    _packet_capture_disable();
    cap.eval(null_packet);
}

TEST_CASE("bad filter", "[PacketCapture]")
{
    auto null_packet = init_null_packet();

    CaptureModule mod;
    MockPacketCapture cap(&mod);

    _packet_capture_enable("this is garbage");
    cap.eval(null_packet);
    CHECK ( (capture_initialized() == false) );

    _packet_capture_enable(
    "port 0 "
    "port 1 "
    "port 2 "
    "port 3 "
    "port 4 "
    "port 5 "
    "port 6 "
    "port 7 "
    "port 8 "
    "port 9 "
    "port 10 "
    "port 11 "
    "port 12 "
    "port 13 "
    "port 14 "
    "port 15 "
    "port 16 "
    "port 17 "
    "port 18 "
    "port 19 "
    );
    cap.eval(null_packet);
    CHECK ( (capture_initialized() == false) );
}

TEST_CASE("bpf filter", "[PacketCapture]")
{
    auto null_packet = init_null_packet();

    const uint8_t match[] =
        //ethernet
        "\xfc\x4d\xd4\x3d\xdc\xb8\x3c\x08\xf6\x2d\x6d\xbf\x08\x00"

        //ipv4
        "\x45\x00\x00\x14\x96\x22\x40\x00\x39\x06\xb1\xeb\x0a\x52\xf0\x52"
        "\x0a\x96";

    const uint8_t non_match[] =
        //ethernet
        "\xfc\x4d\xd4\x3d\xdc\xb8\x3c\x08\xf6\x2d\x6d\xbf\x08\x00"

        //ipv4
        "\x45\x00\x00\x14\x96\x22\x40\x00\x39\x06\xb1\xeb\x0b\x52\xf0\x52"
        "\x0a\x96";

    Packet p_match(false), p_non_match(false);
    DAQ_PktHdr_t daq_hdr;

    p_match.pkth = &daq_hdr;
    p_non_match.pkth = &daq_hdr;

    p_match.pkt = match;
    p_non_match.pkt = non_match;

    p_match.pktlen = sizeof(match);
    p_non_match.pktlen = sizeof(match);

    daq_hdr.pktlen = sizeof(match);
    daq_hdr.ingress_group = -1;
    daq_hdr.egress_group = -1;

    CaptureModule mod;
    MockPacketCapture cap(&mod);

    cap_count_stats.checked = 0;
    cap_count_stats.matched = 0;

    _packet_capture_enable("ip host 10.82.240.82");
    _packet_capture_enable(""); //Test double-enable guard

    cap.write_packet_called = false;
    cap.eval(&p_match);
    CHECK ( cap.write_packet_called );

    cap.write_packet_called = false;
    cap.eval(&p_non_match);
    CHECK ( !cap.write_packet_called );

    cap.write_packet_called = false;
    cap.eval(&p_match);
    CHECK ( cap.write_packet_called );

    CHECK ( (cap_count_stats.checked == 3) );
    CHECK ( (cap_count_stats.matched == 2) );

    REQUIRE ( (cap.pcap.size() >= 2) );
    CHECK ( (cap.pcap.size() == 2) );
    CHECK ( cap.pcap[0] == &p_match );
    CHECK ( cap.pcap[1] == &p_match );

    _packet_capture_disable();
    cap.eval(null_packet);
}
#endif
