//--------------------------------------------------------------------------
// Copyright (C) 2016-2016 Cisco and/or its affiliates. All rights reserved.
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

// packet_cpture.cc author Carter Waxman <cwaxman@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "capture_module.h"

#include <pcap/pcap.h>
#include <sfbpf.h>
#include <string>

#include "framework/inspector.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "main/thread.h"
#include "utils/util.h"

#ifdef UNIT_TEST
#include "catch/catch.hpp"
#endif

#define FILE_NAME "packet_capture.pcap"
#define SNAP_LEN 65535

using namespace std;

static THREAD_LOCAL pcap_t* pcap = nullptr;
static THREAD_LOCAL pcap_dumper_t* dumper = nullptr;
static THREAD_LOCAL struct sfbpf_program bpf;

static inline bool capture_initialized()
{ return dumper != nullptr; }

static inline FILE* open_file(const char* name, bool tmp = false)
{
    if ( tmp )
        return tmpfile();
    else
        return fopen(name, "wb+");
}


//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class PacketCapture : public Inspector
{
public:
    PacketCapture(CaptureModule*) {};

    
    void eval(Packet*) override;
    void tterm() override { capture_term(); };

    virtual void enable(string);
    virtual void disable();

protected:
    virtual void capture_init();
    virtual void capture_term();
    virtual FILE* open_file();
    virtual void write_packet(Packet* p);

private:
    bool enabled = false;
    string filter = "";
};

void PacketCapture::eval(Packet* p)
{
    if ( enabled )
    {
        if ( !capture_initialized() )
            capture_init();
        if ( !bpf.bf_insns || sfbpf_filter(bpf.bf_insns, p->pkt,
                p->pkth->caplen, p->pkth->pktlen) )
            write_packet(p);
    }
    else if ( capture_initialized() )
        capture_term();
}

void PacketCapture::enable(string filter)
{
    if ( enabled == true )
    {
        WarningMessage("Conflicting packet capture already in progress.\n");
        return;
    }
    this->filter = filter;
    enabled = true;
}

void PacketCapture::disable()
{
    enabled = false;
    LogMessage("Packet capture disabled\n");
}

void PacketCapture::capture_init()
{
    if ( sfbpf_compile(SNAP_LEN, DLT_EN10MB, &bpf, filter.c_str(), 1, 0) < 0 )
    {
        WarningMessage("Unable to compile BPF filter\n");
        disable();
        return;
    }
    if ( !sfbpf_validate(bpf.bf_insns, bpf.bf_len) )
    {
        WarningMessage("Unable to validate BPF filter\n");
        disable();
        capture_term();
        return;
    }

    FILE* fh = open_file();
    if ( !fh )
    {
        WarningMessage("Could not open dump file\n");
        disable();
        capture_term();
        return;
    }

    pcap = pcap_open_dead(DLT_EN10MB, SNAP_LEN);
    dumper = pcap_dump_fopen(pcap, fh);
    if ( !dumper )
    {
        WarningMessage("Could not initialize dump file\n");
        disable();
        capture_term();
    }
}

FILE* PacketCapture::open_file()
{
    string fname;

    get_instance_file(fname, FILE_NAME);
    return ::open_file(fname.c_str());
}

void PacketCapture::capture_term()
{
    if ( dumper )
    {
        pcap_dump_close(dumper); //this closes open file handle
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
    struct pcap_pkthdr pkth;
    pkth.caplen = p->pkth->caplen;
    pkth.len = p->pkth->pktlen;
    pkth.ts = p->pkth->ts;
    pcap_dump((unsigned char*)dumper, &pkth, p->pkt);
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new CaptureModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* pc_ctor(Module* m)
{
    static THREAD_LOCAL unsigned s_init = true;

    if ( !s_init )
        return nullptr;

    return new PacketCapture((CaptureModule*)m);
}

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

const BaseApi* nin_packet_capture = &pc_api.base;

#ifdef UNIT_TEST

class MockPacketCapture : public PacketCapture
{
public:
    Packet null_packet;
    DAQ_PktHdr_t null_hdr;
    bool write_packet_called = false;
    FILE* fh = nullptr;

    MockPacketCapture(CaptureModule* m) : PacketCapture(m)
    {
        null_packet.pkt = nullptr;
        null_packet.pkth = &null_hdr;
        null_hdr.caplen = 0;
        null_hdr.pktlen = 0;
    }
    
protected:
    FILE* open_file() override
    {
        return fh = ::open_file(nullptr, true);
    }

    void write_packet(Packet* p) override
    {
        if ( p && p->pkt )
            PacketCapture::write_packet(p);
        write_packet_called = true;
    }
};


TEST_CASE("toggle", "[PacketCapture]")
{
    auto mod = (CaptureModule*)mod_ctor();
    MockPacketCapture cap(mod);
    
    cap.write_packet_called = false;
    cap.eval(&cap.null_packet);
    CHECK ( !cap.write_packet_called );

    cap.write_packet_called = false;
    cap.enable("");
    cap.eval(&cap.null_packet);
    CHECK ( cap.write_packet_called );
    
    cap.write_packet_called = false;
    cap.disable();
    cap.eval(&cap.null_packet);
    CHECK ( !cap.write_packet_called );

    mod_dtor(mod);
}

TEST_CASE("lazy init", "[PacketCapture]")
{
    CaptureModule mod;
    MockPacketCapture cap(&mod);
    
    CHECK ( !capture_initialized() );

    cap.eval(&cap.null_packet);
    CHECK ( !capture_initialized() );

    cap.enable("");
    CHECK ( !capture_initialized() );

    cap.eval(&cap.null_packet);
    CHECK ( capture_initialized() );

    cap.disable();
    CHECK ( capture_initialized() );

    cap.eval(&cap.null_packet);
    CHECK ( !capture_initialized() );
}

TEST_CASE("pcap init", "[PacketCapture]")
{
    CaptureModule mod;
    MockPacketCapture cap(&mod);
    
    cap.enable("");
    cap.eval(&cap.null_packet);

    fseek(cap.fh, 0, SEEK_SET);
    auto pcap = pcap_fopen_offline(cap.fh, nullptr);

    CHECK ( pcap );

    free(pcap);

    cap.disable();
    cap.eval(&cap.null_packet);
}

TEST_CASE("write packet", "[PacketCapture]")
{
    const uint8_t cooked[] = "AbCdEfGhIjKlMnOpQrStUvWxYz";
    struct pcap_pkthdr hdr;

    Packet p;
    DAQ_PktHdr_t daq_hdr;
    p.pkt = cooked;
    p.pkth = &daq_hdr;

    daq_hdr.caplen = sizeof(cooked);
    daq_hdr.pktlen = sizeof(cooked);
    time_t ts = time(nullptr);

    CaptureModule mod;
    MockPacketCapture cap(&mod);
    
    cap.enable("");
    cap.eval(&p);

    fseek(cap.fh, 0, SEEK_SET);
    auto pcap = pcap_fopen_offline(cap.fh, nullptr);
    auto packet = pcap_next(pcap, &hdr);

    REQUIRE ( packet );
    CHECK ( !memcmp(cooked, packet, fmax(hdr.caplen, sizeof(cooked))) );

    free(pcap);

    cap.disable();
    cap.eval(&cap.null_packet);
}

TEST_CASE("bad filter", "[PacketCapture]")
{
    CaptureModule mod;
    MockPacketCapture cap(&mod);

    cap.enable("this is garbage");
    cap.eval(&cap.null_packet);
    CHECK ( !capture_initialized() );
}

TEST_CASE("bpf filter", "[PacketCapture]")
{
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

    struct pcap_pkthdr hdr;

    Packet p;
    DAQ_PktHdr_t daq_hdr;
    p.pkth = &daq_hdr;

    daq_hdr.caplen = sizeof(match);
    daq_hdr.pktlen = sizeof(match);
    time_t ts = time(nullptr);

    CaptureModule mod;
    MockPacketCapture cap(&mod);
    
    cap.enable("ip host 10.82.240.82");
    cap.enable(""); //Test double-enable guard

    p.pkt = match;
    cap.write_packet_called = false;
    cap.eval(&p);
    CHECK ( cap.write_packet_called );

    p.pkt = non_match;
    cap.write_packet_called = false;
    cap.eval(&p);
    CHECK ( !cap.write_packet_called );

    p.pkt = match;
    cap.write_packet_called = false;
    cap.eval(&p);
    CHECK ( cap.write_packet_called );

    fseek(cap.fh, 0, SEEK_SET);
    auto pcap = pcap_fopen_offline(cap.fh, nullptr);

    auto packet = pcap_next(pcap, &hdr);
    REQUIRE ( packet );
    CHECK ( !memcmp(match, packet, fmax(hdr.caplen, sizeof(match))) );

    packet = pcap_next(pcap, &hdr);
    REQUIRE ( packet );
    CHECK ( !memcmp(match, packet, fmax(hdr.caplen, sizeof(match))) );

    free(pcap);

    cap.disable();
    cap.eval(&cap.null_packet);
}
#endif
