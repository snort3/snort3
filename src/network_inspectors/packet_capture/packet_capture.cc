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

// packet_capture.cc author Carter Waxman <cwaxman@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "packet_capture.h"

#include <pcap.h>

#include "framework/inspector.h"
#include "log/messages.h"
#include "protocols/packet.h"

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

static bool bpf_compile_and_validate()
{
    // FIXIT-M This BPF compilation is not threadsafe and should be handled by the main thread
    // and this call should use DLT from DAQ rather then hard coding DLT_EN10MB
    if ( pcap_compile_nopcap(SNAP_LEN, DLT_EN10MB, &bpf,
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
    get_instance_file(fname, FILE_NAME);

    pcap = pcap_open_dead(DLT_EN10MB, SNAP_LEN);
    dumper = pcap ? pcap_dump_open(pcap, fname.c_str()) : nullptr;

    if (dumper)
        return true;
    else
        WarningMessage("Could not initialize dump file\n");

    return false;
}

// for unit test
static void _packet_capture_enable(const string& f)
{
    if ( !config.enabled )
    {
        config.filter = f;
        config.enabled = true;
    }
}

// for unit test
static void _packet_capture_disable()
{
    config.enabled = false;
    LogMessage("Packet capture disabled\n");
}

// -----------------------------------------------------------------------------
// non-static functions
// -----------------------------------------------------------------------------

void packet_capture_enable(const string& f)
{

    _packet_capture_enable(f);

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

void PacketCapture::eval(Packet* p)
{
    if ( config.enabled )
    {
        if ( !capture_initialized() )
            if ( !capture_init() )  
                return;

        if ( !bpf.bf_insns || bpf_filter(bpf.bf_insns, p->pkt,
                p->pkth->caplen, p->pkth->pktlen) )
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
    //DAQ_PktHdr_t is compatible with pcap_pkthdr
    pcap_dump((unsigned char*)dumper, (const pcap_pkthdr*)p->pkth, p->pkt);
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
    IT_PROBE,
    PROTO_BIT__ANY_TYPE,
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
static Packet* init_null_packet()
{
    static Packet p(false);
    static DAQ_PktHdr_t h;

    p.pkt = nullptr;
    p.pkth = &h;
    h.caplen = 0;
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
        pcap.push_back(p);
        write_packet_called = true;
    }

    bool capture_init() override
    {
        if (bpf_compile_and_validate())
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

TEST_CASE("blank filter", "[PacketCapture]")
{
    auto null_packet = init_null_packet();

    const uint8_t cooked[] = "AbCdEfGhIjKlMnOpQrStUvWxYz";

    Packet p(false);
    DAQ_PktHdr_t daq_hdr;
    p.pkt = cooked;
    p.pkth = &daq_hdr;

    daq_hdr.caplen = sizeof(cooked);
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

    daq_hdr.caplen = sizeof(match);
    daq_hdr.pktlen = sizeof(match);

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
