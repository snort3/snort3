//--------------------------------------------------------------------------
// Copyright (C) 2016-2017 Cisco and/or its affiliates. All rights reserved.
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
#include <sfbpf.h>

#include "framework/inspector.h"
#include "log/messages.h"
#include "protocols/packet.h"

#ifdef UNIT_TEST
#include "catch/catch.hpp"
#endif

#include "capture_module.h"

using namespace std;

#define FILE_NAME "packet_capture.pcap"
#define SNAP_LEN 65535

static CaptureConfig config;

static THREAD_LOCAL pcap_t* pcap = nullptr;
static THREAD_LOCAL pcap_dumper_t* dumper = nullptr;
static THREAD_LOCAL struct sfbpf_program bpf;

static inline bool capture_initialized()
{ return dumper != nullptr; }

void packet_capture_enable(const string& f)
{
    if ( !config.enabled )
    {
        config.filter = f;
        config.enabled = true;
    }
    else
        WarningMessage("Conflicting packet capture already in progress.\n");
}

void packet_capture_disable()
{
    config.enabled = false;
    LogMessage("Packet capture disabled\n");
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class PacketCapture : public Inspector
{
public:
    PacketCapture(CaptureModule*);

    void eval(Packet*) override;
    void tterm() override { capture_term(); }

protected:
    virtual bool capture_init();
    virtual void capture_term();
    virtual pcap_dumper_t* open_dump(pcap_t*, const char*);
    virtual void write_packet(Packet* p);
};

PacketCapture::PacketCapture(CaptureModule* m)
{ m->get_config(config); }

void PacketCapture::eval(Packet* p)
{
    if ( config.enabled )
    {
        if ( !capture_initialized() )
            if ( !capture_init() )
                return;

        if ( !bpf.bf_insns || sfbpf_filter(bpf.bf_insns, p->pkt,
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

bool PacketCapture::capture_init()
{
    if ( sfbpf_compile(SNAP_LEN, DLT_EN10MB, &bpf,
        config.filter.c_str(), 1, 0) >= 0 )
    {
        if ( sfbpf_validate(bpf.bf_insns, bpf.bf_len) )
        {
            string fname;
            get_instance_file(fname, FILE_NAME);

            pcap = pcap_open_dead(DLT_EN10MB, SNAP_LEN);
            dumper = open_dump(pcap, fname.c_str());

            if ( dumper )
                return true;
            else
                WarningMessage("Could not initialize dump file\n");
        }
        else
            WarningMessage("Unable to validate BPF filter\n");
    }
    else
        WarningMessage("Unable to compile BPF filter\n");

    packet_capture_disable();
    capture_term();
    return false;
}

pcap_dumper_t* PacketCapture::open_dump(pcap_t* pcap, const char* fname)
{ return pcap_dump_open(pcap, fname); }

void PacketCapture::capture_term()
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
    sfbpf_freecode(&bpf);
}

void PacketCapture::write_packet(Packet* p)
{
    //DAQ_PktHdr_t is compatible with pcap_pkthdr
    pcap_dump((unsigned char*)dumper, (pcap_pkthdr*)p->pkth, p->pkt);
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
    IT_PACKET,
    (uint16_t)PktType::ANY,
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
    pcap_dumper_t* open_dump(pcap_t*, const char*) override
    { return (pcap_dumper_t*)1; }

    void write_packet(Packet* p) override
    {
        pcap.push_back(p);
        write_packet_called = true;
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
    packet_capture_enable("");
    cap.eval(null_packet);
    CHECK ( cap.write_packet_called );

    cap.write_packet_called = false;
    packet_capture_disable();
    cap.eval(null_packet);
    CHECK ( !cap.write_packet_called );
}

TEST_CASE("lazy init", "[PacketCapture]")
{
    auto null_packet = init_null_packet();

    auto mod = (CaptureModule*)mod_ctor();
    auto real_cap = (PacketCapture*)pc_ctor(mod);

    CHECK ( !capture_initialized() );

    real_cap->eval(null_packet);
    CHECK ( !capture_initialized() );

    pc_dtor(real_cap);
    MockPacketCapture cap(mod);

    packet_capture_enable("");
    CHECK ( !capture_initialized() );

    cap.eval(null_packet);
    CHECK ( capture_initialized() );

    packet_capture_disable();
    CHECK ( capture_initialized() );

    cap.eval(null_packet);
    CHECK ( !capture_initialized() );

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

    packet_capture_enable("");
    cap.eval(&p);

    REQUIRE ( cap.pcap.size() );
    CHECK ( cap.pcap[0] == &p );

    packet_capture_disable();
    cap.eval(null_packet);
}

TEST_CASE("bad filter", "[PacketCapture]")
{
    auto null_packet = init_null_packet();

    CaptureModule mod;
    MockPacketCapture cap(&mod);

    packet_capture_enable("this is garbage");
    cap.eval(null_packet);
    CHECK ( !capture_initialized() );

    packet_capture_enable(
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
    CHECK ( !capture_initialized() );
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

    packet_capture_enable("ip host 10.82.240.82");
    packet_capture_enable(""); //Test double-enable guard

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

    packet_capture_disable();
    cap.eval(null_packet);
}
#endif
