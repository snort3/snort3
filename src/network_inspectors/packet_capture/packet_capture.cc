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

using namespace std;

static THREAD_LOCAL FILE* fh = nullptr;
static THREAD_LOCAL pcap_t* pcap = nullptr;
static THREAD_LOCAL pcap_dumper_t* dumper = nullptr;
static THREAD_LOCAL struct bpf_program bpf;

static void open_file(const char* name, bool tmp = false)
{
    if ( !fh )
    {
        if ( tmp )
            fh = tmpfile();
        else
            fh = fopen(name, "wb+");
    }
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class PacketCapture : public Inspector
{
public:
    PacketCapture(CaptureModule*) {};

    
    void eval(Packet*) override;
    void tterm() override { close_file(); };

    virtual void enable(string);
    virtual void disable();

protected:
    virtual void open_file();
    virtual void write_packet(Packet* p);
    virtual void close_file();

private:
    bool enabled = false;
    string bpf_expr;

    void init_capture();
};

void PacketCapture::eval(Packet* p)
{
    if ( enabled )
    {
        if ( !fh )
        {
            open_file();
            init_capture();
        }

        write_packet(p);
    }
    else
    {
        if ( fh )
            close_file();
    }
}

void PacketCapture::enable(string filter)
{
    bpf_expr = filter;
    enabled = true;
}

void PacketCapture::disable()
{
    enabled = false;
}

void PacketCapture::open_file()
{
    string fname;

    get_instance_file(fname, FILE_NAME);
    ::open_file(fname.c_str());
}

void PacketCapture::init_capture()
{
    bool error = false;

    pcap = pcap_open_dead(DLT_RAW, 65535);
    dumper = pcap_dump_fopen(pcap, fh);

    if ( pcap_compile(pcap, &bpf, bpf_expr.c_str(), 1, 0) == -1 )
    {
        ErrorMessage("Could not compile bpf filter.");
        error = true;
    }
    else if ( pcap_setfilter(pcap, &bpf) == -1 )
    {
        ErrorMessage("Could not install bpf filter.");
        error = true;
    }
    else if ( !dumper )
    {
        ErrorMessage("Could not open dump file.");
        error = true;
    }

    if ( error )
    {
        ErrorMessage("Disabling packet capture.");
        disable();
        close_file();
    }
}

void PacketCapture::close_file()
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
    if ( fh )
    {
        fclose(fh);
        fh = nullptr;
    }
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
    bool write_packet_called = false;
    MockPacketCapture(CaptureModule* m) : PacketCapture(m) {};
    
protected:
    void open_file() override
    {
        if ( !fh )
            ::open_file(nullptr, true);
    };

    void write_packet(Packet* p) override
    {
        if ( p )
            PacketCapture::write_packet(p);
        write_packet_called = true;
    };
};

TEST_CASE("toggle", "[PacketCapture]")
{
    CaptureModule mod;
    MockPacketCapture cap(&mod);
    
    cap.write_packet_called = false;
    cap.eval(nullptr);
    CHECK( !cap.write_packet_called );

    cap.write_packet_called = false;
    cap.enable("");
    cap.eval(nullptr);
    CHECK( cap.write_packet_called );
    
    cap.write_packet_called = false;
    cap.disable();
    cap.eval(nullptr);
    CHECK( !cap.write_packet_called );
}

TEST_CASE("lazy file handling", "[PacketCapture]")
{
    CaptureModule mod;
    MockPacketCapture cap(&mod);
    
    CHECK( !fh );

    cap.eval(nullptr);
    CHECK( !fh );

    cap.enable("");
    CHECK( !fh );

    cap.eval(nullptr);
    CHECK( fh );

    cap.disable();
    CHECK( fh );

    cap.eval(nullptr);
    CHECK( !fh );
}

TEST_CASE("pcap init", "[PacketCapture]")
{
    CaptureModule mod;
    MockPacketCapture cap(&mod);
    
    cap.enable("");
    cap.eval(nullptr);

    fseek(fh, 0, SEEK_SET);
    auto pcap = pcap_fopen_offline(fh, nullptr);

    CHECK( pcap );

    free(pcap);

    cap.disable();
    cap.eval(nullptr);
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

    fseek(fh, 0, SEEK_SET);
    auto pcap = pcap_fopen_offline(fh, nullptr);
    auto packet = pcap_next(pcap, &hdr);

    REQUIRE( packet );
    CHECK( !memcmp(cooked, packet, fmax(hdr.caplen, sizeof(cooked))) );

    free(pcap);

    cap.disable();
    cap.eval(nullptr);
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
    p.pkt = match;
    cap.eval(&p);
    p.pkt = non_match;
    cap.eval(&p);
    p.pkt = match;
    cap.eval(&p);

    fseek(fh, 0, SEEK_SET);
    auto pcap = pcap_fopen_offline(fh, nullptr);

    auto packet = pcap_next(pcap, &hdr);
    REQUIRE( packet );
    CHECK( !memcmp(match, packet, fmax(hdr.caplen, sizeof(match))) );

    packet = pcap_next(pcap, &hdr);
    REQUIRE( packet );
    CHECK( !memcmp(match, packet, fmax(hdr.caplen, sizeof(match))) );

    free(pcap);

    cap.disable();
    cap.eval(nullptr);
}
#endif
