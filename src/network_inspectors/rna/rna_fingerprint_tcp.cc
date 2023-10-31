//--------------------------------------------------------------------------
// Copyright (C) 2020-2023 Cisco and/or its affiliates. All rights reserved.
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

// rna_fingerprint_tcp.cc author Silviu Minut <sminut@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "rna_fingerprint_tcp.h"

#include <sstream>

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

#include "log/messages.h"
#include "protocols/ipv4.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"
#include "protocols/tcp_options.h"

#include "rna_flow.h"

using namespace snort;
using namespace std;

static THREAD_LOCAL TcpFpProcessor* tcp_fp_processor = nullptr;

unsigned RNAFlow::inspector_id = 0;

static int parse_fp_element(const string& data, vector<FpElement>& fpe)
{
    istringstream in(data);
    string tok;

    while ( in >> tok )
        fpe.emplace_back(tok);
    return 1;
}

TcpFpProcessor* get_tcp_fp_processor()
{
    return tcp_fp_processor;
}

void set_tcp_fp_processor(TcpFpProcessor* processor)
{
    tcp_fp_processor = processor;
}

namespace snort
{

TcpFingerprint::TcpFingerprint(const RawFingerprint& rfp)
{
    fpid = rfp.fpid;
    fp_type = rfp.fp_type;
    fpuuid = rfp.fpuuid;
    ttl = rfp.ttl;

    parse_fp_element(rfp.tcp_window, tcp_window);
    parse_fp_element(rfp.mss, mss);
    parse_fp_element(rfp.id, id);
    parse_fp_element(rfp.topts, topts);
    parse_fp_element(rfp.ws, ws);
    df = rfp.df;
}

bool TcpFingerprint::operator==(const TcpFingerprint& y) const
{
    return (
        fpid == y.fpid &&
        fp_type == y.fp_type &&
        fpuuid == y.fpuuid &&
        ttl == y.ttl &&
        equal(tcp_window.begin(), tcp_window.end(), y.tcp_window.begin()) &&
        equal(mss.begin(), mss.end(), y.mss.begin()) &&
        equal(id.begin(), id.end(), y.id.begin()) &&
        equal(topts.begin(), topts.end(), y.topts.begin()) &&
        df == y.df);
}

bool TcpFpProcessor::push(const TcpFingerprint& tfp)
{
    const auto& result = tcp_fps.emplace(tfp.fpid, tfp);
    if (!result.second)
        WarningMessage("TcpFpProcessor: ignoring previously seen fingerprint id: %d\n", tfp.fpid);
    return result.second;
}

void TcpFpProcessor::make_tcp_fp_tables(TCP_FP_MODE mode)
{
    auto* fptable = (mode == TCP_FP_MODE::SERVER ?
        table_tcp_server : table_tcp_client);

    for (size_t i = 0; i < table_size; i++)
        fptable[i].clear();

    for (const auto& tfpit : tcp_fps)
    {
        const auto& tfp = tfpit.second;
        for (const auto& fpe : tfp.tcp_window)
        {
            switch (fpe.type)
            {
            case FpElementType::RANGE:
                for (int i = fpe.d.range.min; i <= fpe.d.range.max; i++)
                    fptable[i].emplace_back(&tfp);
                break;
            default:
                break;
            }
        }
    }
}

static inline bool is_mss_good(const FpTcpKey& key, const vector<FpElement>& tfp_mss)
{
    for (const auto& fpe_mss : tfp_mss)
    {
        switch (fpe_mss.type)
        {
        case FpElementType::RANGE:
            if (key.mss >= fpe_mss.d.range.min and key.mss <= fpe_mss.d.range.max)
                return true;
            break;
        case FpElementType::SYN_MATCH:
            //if synmss is negative, it means that client didn't send MSS option
            if ((key.synmss  >= 0) and ((!fpe_mss.d.value and key.mss <= key.synmss) or
                (fpe_mss.d.value and ((key.synmss < fpe_mss.d.value and key.mss <= key.synmss) or
                (key.synmss >= fpe_mss.d.value and key.mss <= fpe_mss.d.value)))))
                return true;
            break;
        case FpElementType::DONT_CARE:
        case FpElementType::SYNTS:
            return true;
        default:
            break;
        }
    }
    return false;
}

static inline bool is_ws_good(const FpTcpKey& key, const vector<FpElement>& tfp_ws)
{
    if (key.ws_pos >= 0)
    {
        for (const auto& fpe_ws : tfp_ws)
        {
            switch (fpe_ws.type)
            {
            case FpElementType::RANGE:
                if (key.ws >= fpe_ws.d.range.min and key.ws <= fpe_ws.d.range.max)
                    return true;
                break;
            case FpElementType::DONT_CARE:
                return true;
            default:
                break;
            }
        }
        return false;
    }
    return true;
}

static inline bool is_option_good(const int& optpos, const int& fp_optpos,
    const uint8_t* optorder, const uint8_t* fp_optorder)
{
    if (optpos != fp_optpos)
        return false;

    for (int i = 0; i < optpos; i++)
    {
        if (optorder[i] != fp_optorder[i])
            return false;
    }
    return true;
}

static inline bool is_ts_good(const FpTcpKey& key, const vector<FpElement>& topts,
    const int& optpos, const uint8_t* optorder, uint8_t* fp_optorder)
{
    if (key.syn_timestamp)
        return false;

    int i = 0;
    for (; i < key.num_syn_tcpopts; i++)
    {
        if (key.syn_tcpopts[i] == (uint8_t) tcp::TcpOptCode::TIMESTAMP)
            break;
    }
    if (i == key.num_syn_tcpopts)
        return false;

    int fp_optpos = 0;
    for (const auto& fpe_topts : topts)
    {
        for (i = 0; i < key.num_syn_tcpopts; i++)
        {
            if (key.syn_tcpopts[i] == fpe_topts.d.range.min)
            {
                if (key.syn_tcpopts[i] != (uint8_t) tcp::TcpOptCode::TIMESTAMP)
                    fp_optorder[fp_optpos++] = key.syn_tcpopts[i];
                break;
            }
        }
    }
    if (optpos != fp_optpos)
        return false;

    for (i = 0; i < optpos and i < 4; i++)
    {
        if (optorder[i] != fp_optorder[i])
            return false;
    }
    return true;
}

const TcpFingerprint* TcpFpProcessor::get_tcp_fp(const FpTcpKey& key, uint8_t ttl,
    TCP_FP_MODE mode) const
{
    uint8_t optorder[4];
    uint8_t fp_optorder[4];
    int optpos;
    int fp_optpos;
    int i;
    uint32_t fptype;

    const vector<const snort::TcpFingerprint*>* fptable;

    if (mode == TCP_FP_MODE::SERVER)
    {
        fptable = table_tcp_server;
        fptype = key.isIpv6 ?
            FpFingerprint::FpType::FP_TYPE_SERVER6 :
            FpFingerprint::FpType::FP_TYPE_SERVER;
    }
    else
    {
        fptable = table_tcp_client;
        fptype = key.isIpv6 ?
            FpFingerprint::FpType::FP_TYPE_CLIENT6 :
            FpFingerprint::FpType::FP_TYPE_CLIENT;
    }

    const auto& tfpvec = fptable[key.tcp_window];
    for (const auto& tfp : tfpvec)
    {
        if (tfp->fp_type != fptype or !is_mss_good(key, tfp->mss))
            continue;

        if ( (key.isIpv6 || key.df == tfp->df) &&  // don't check df for ipv6
            ttl <= tfp->ttl &&
            (tfp->ttl < MAXIMUM_FP_HOPS || ttl >= (tfp->ttl - MAXIMUM_FP_HOPS)))
        {
            if (!is_ws_good(key, tfp->ws))
                continue;

            if (mode == TCP_FP_MODE::SERVER)
            {
                //create array of options in the order seen in server packet
                for (i=0, optpos=0; i<TCP_OPTLENMAX && optpos<4; i++)
                {
                    if (i == key.ws_pos)
                        optorder[optpos++] = (uint8_t) tcp::TcpOptCode::WSCALE;
                    else if (i == key.mss_pos)
                        optorder[optpos++] = (uint8_t) tcp::TcpOptCode::MAXSEG;
                    else if (i == key.sackok_pos)
                        optorder[optpos++] = (uint8_t) tcp::TcpOptCode::SACKOK;
                    else if (i == key.timestamp_pos)
                        optorder[optpos++] = (uint8_t) tcp::TcpOptCode::TIMESTAMP;
                }

                //create array of options from fingerprint that were present in client packet.
                //Ordered by fingerprint option order
                fp_optpos = 0;
                for (const auto& fpe_topts : tfp->topts)
                {
                    for (i=0; i<key.num_syn_tcpopts; i++)
                    {
                        if (key.syn_tcpopts[i] == fpe_topts.d.range.min)
                        {
                            fp_optorder[fp_optpos++] = key.syn_tcpopts[i];
                            break;
                        }
                    }
                }

                //if number, type, or order of option in SYN mismatch those in FP,
                //goto next check.
                if (is_option_good(optpos, fp_optpos, optorder, fp_optorder))
                    return tfp;

                //number and type of options didn't match between SYN and fingerprint.
                //Ignore Timestamp option if present in SYN.
                if (!is_ts_good(key, tfp->topts, optpos, optorder, fp_optorder))
                    continue;

                return tfp;
            }
            else
            {
                for (i=0, optpos=0; i<TCP_OPTLENMAX && optpos<4; i++)
                {
                    if (i == key.ws_pos)
                        optorder[optpos++] = (uint8_t) tcp::TcpOptCode::WSCALE;
                    else if (i == key.mss_pos)
                        optorder[optpos++] = (uint8_t) tcp::TcpOptCode::MAXSEG;
                    else if (i == key.sackok_pos)
                        optorder[optpos++] = (uint8_t) tcp::TcpOptCode::SACKOK;
                    else if (i == key.timestamp_pos)
                        optorder[optpos++] = (uint8_t) tcp::TcpOptCode::TIMESTAMP;
                }

                auto fpe_topts = tfp->topts.begin();
                for (i = 0; i<optpos && fpe_topts != tfp->topts.end(); i++, fpe_topts++)
                {
                    if (optorder[i] != fpe_topts->d.range.min)
                        break;
                }

                // if there were more elements in this fingerprint or
                // there was a mismatch between this fingerprint and the
                // key, go to the next fingerprint in the store
                if (fpe_topts != tfp->topts.end() || i < optpos)
                    continue;

                return tfp;
            }
        }
    }
    return nullptr;
}


static int get_tcp_option(const Packet* p, tcp::TcpOptCode opt_code, int& pos)
{
    int maxops = (int) p->ptrs.tcph->options_len();
    if (TCP_OPTLENMAX < maxops)
    {
        pos = -1;
        return -1;
    }

    pos = 0;
    tcp::TcpOptIterator opt_iter(p->ptrs.tcph, p);
    for (const tcp::TcpOption& opt : opt_iter)
    {
        if (opt.code == opt_code)
        {
            switch (opt.code)
            {
            case tcp::TcpOptCode::MAXSEG:
                return ntohs(*((const uint16_t*)(opt.data)));

            case tcp::TcpOptCode::NOP:
                return 1;

            case tcp::TcpOptCode::SACKOK:
                return 1;

            case tcp::TcpOptCode::WSCALE:
                return opt.data[0] & 0xff;

            case tcp::TcpOptCode::TIMESTAMP:
                return ntohs(*((const uint32_t*)(opt.data)));

            default:
                break;
            }
        }

        pos++;
    }

    pos = -1;
    return -1;
}

const TcpFingerprint* TcpFpProcessor::get(const Packet* p, RNAFlow* flowp) const
{
    FpTcpKey fpk{};
    bool mssOptionPresent = false;

    /* build a key for the lookup */
    if (p->is_ip6())
        fpk.isIpv6 = true;
    else if (p->ptrs.ip_api.get_ip4h()->df())
        fpk.df = true;

    fpk.tcp_window = p->ptrs.tcph->win();

    fpk.mss = get_tcp_option(p, tcp::TcpOptCode::MAXSEG, fpk.mss_pos);
    if (fpk.mss_pos >= 0)
    {
        get_tcp_option(p, tcp::TcpOptCode::SACKOK, fpk.sackok_pos);
        fpk.ws = get_tcp_option(p, tcp::TcpOptCode::WSCALE, fpk.ws_pos);
        get_tcp_option(p, tcp::TcpOptCode::TIMESTAMP, fpk.timestamp_pos);
        mssOptionPresent = true;
    }

    TCP_FP_MODE traffic_source = p->ptrs.tcph->is_ack() ? TCP_FP_MODE::SERVER : TCP_FP_MODE::CLIENT;

    if (traffic_source == TCP_FP_MODE::SERVER)
    {
        if (!flowp)
            return nullptr;

        if (!mssOptionPresent)
            return nullptr;

        fpk.synmss = flowp->state.initial_mss;
        fpk.num_syn_tcpopts = flowp->state.numopts;
        fpk.syn_tcpopts = flowp->state.tcpopts;
        fpk.syn_timestamp = flowp->state.timestamp;
    }
    else
    {
        if (!mssOptionPresent)
        {
            //client becomes unknown when client does not sent MSS option
            return nullptr;
        }
    }

    /* run the search and return the result */
    const TcpFingerprint* fp = get_tcp_fp(fpk, p->ptrs.ip_api.ttl(), traffic_source);

    return fp;
}

}

void RNAFlow::init()
{
    inspector_id = snort::FlowData::create_flow_data_id();
}

bool FpFingerprintState::set(const Packet* p)
{
    int pos = 0;
    numopts = 0;
    initial_mss = get_tcp_option(p, tcp::TcpOptCode::MAXSEG, pos);
    tcpopts[numopts++] = (uint8_t) tcp::TcpOptCode::MAXSEG;

    get_tcp_option(p, tcp::TcpOptCode::SACKOK, pos);
    if (pos >= 0)
        tcpopts[numopts++] = (uint8_t) tcp::TcpOptCode::SACKOK;

    get_tcp_option(p, tcp::TcpOptCode::WSCALE, pos);
    if (pos >= 0)
        tcpopts[numopts++] = (uint8_t) tcp::TcpOptCode::WSCALE;

    timestamp = get_tcp_option(p, tcp::TcpOptCode::TIMESTAMP, pos);
    if (pos >= 0)
        tcpopts[numopts++] = (uint8_t) tcp::TcpOptCode::TIMESTAMP;
    else
        timestamp = -1;
    timeout = p->pkth->ts.tv_sec;

    return true;
}


#ifdef UNIT_TEST

TEST_CASE("get_tcp_fp_processor", "[rna_fingerprint_tcp]")
{
    TcpFpProcessor* tfp = get_tcp_fp_processor();
    CHECK(tfp == tcp_fp_processor);
}

TEST_CASE("clear_fingerprint", "[rna_fingerprint_tcp]")
{
    TcpFingerprint fpx;
    fpx.fpuuid.clear();

    RawFingerprint rawfp;
    rawfp.fpid = 948;
    rawfp.fp_type = 1;
    rawfp.fpuuid = "12345678-1234-1234-1234-123456789012";
    rawfp.ttl = 64;
    rawfp.tcp_window = "10 20 30-40 50 60-70";
    rawfp.mss = "X";
    rawfp.id = "X";
    rawfp.topts = "2 3 4 8";
    rawfp.ws = "6";
    rawfp.df = true;

    TcpFingerprint tfp(rawfp);
    tfp.clear();
    CHECK(tfp == fpx);
}

TEST_CASE("parse_fp_element", "[rna_fingerprint_tcp]")
{
    vector<string> str_elements = {"10", "20", "30-40", "50", "60-70"};
    vector<FpElement> vfpe;
    string str;
    for (const auto& tok : str_elements)
    {
        str += tok + " ";
        vfpe.emplace_back(FpElement(tok));
    }

    vector<FpElement> vfpe_test;
    parse_fp_element(str, vfpe_test);
    CHECK( equal(vfpe.begin(), vfpe.end(), vfpe_test.begin()) );
}

TEST_CASE("raw_to_tcp_fp", "[rna_fingerprint_tcp]")
{
    RawFingerprint rawfp;
    rawfp.fpid = 948;
    rawfp.fp_type = 1;
    rawfp.fpuuid = "12345678-1234-1234-1234-123456789012";
    rawfp.ttl = 64;
    rawfp.tcp_window = "10 20 30-40 50 60-70";
    rawfp.mss = "X";
    rawfp.id = "X";
    rawfp.topts = "2 3 4 8";
    rawfp.ws = "6";
    rawfp.df = true;

    TcpFingerprint tfpe;
    tfpe.fpid = rawfp.fpid;
    tfpe.fp_type = rawfp.fp_type;
    tfpe.fpuuid = rawfp.fpuuid;
    tfpe.ttl = rawfp.ttl;
    tfpe.tcp_window = vector<FpElement> {
        FpElement("10"), FpElement("20"), FpElement("30-40"),
        FpElement("50"), FpElement("60-70") };
    tfpe.mss = vector<FpElement> { FpElement("X") };
    tfpe.id = vector<FpElement> { FpElement("X") };
    tfpe.topts = vector<FpElement> {
        FpElement("2"), FpElement("3"), FpElement("4"), FpElement("8") };
    tfpe.ws.emplace_back(FpElement("6"));
    tfpe.df = rawfp.df;

    TcpFingerprint tfp_test(rawfp);

    CHECK(tfpe == tfp_test);
}

TEST_CASE("get_tcp_fp", "[rna_fingerprint_tcp]")
{
    set_tcp_fp_processor(new TcpFpProcessor);
    TcpFpProcessor* processor = get_tcp_fp_processor();

    // Push some fingerprints to the processor:
    RawFingerprint rawfp;
    rawfp.fpid = 948;
    rawfp.fp_type = 1;
    rawfp.fpuuid = "12345678-1234-1234-1234-123456789012";
    rawfp.ttl = 64;
    rawfp.tcp_window = "-1";
    rawfp.mss = "X";
    rawfp.id = "X";
    rawfp.topts = "2 3 4 8";
    rawfp.ws = "6";
    rawfp.df = true;
    processor->push(rawfp);
    TcpFingerprint f948(rawfp);

    rawfp.fpid = 30962;
    rawfp.fp_type = 2;
    rawfp.fpuuid = "12345678-1234-1234-1234-123456789013";
    rawfp.ttl = 64;
    rawfp.tcp_window = "-1";
    rawfp.mss = "X";
    rawfp.id = "X";
    rawfp.topts = "2 4 8 3";
    rawfp.ws = "8";
    rawfp.df = true;
    processor->push(rawfp);
    TcpFingerprint f30962(rawfp);

    rawfp.fpid = 110005;
    rawfp.fp_type = 10;
    rawfp.fpuuid = "12345678-1234-1234-1234-123456789014";
    rawfp.ttl = 64;
    rawfp.tcp_window = "5712-5760";
    rawfp.mss = "X";
    rawfp.id = "X";
    rawfp.topts = "2 4 8 3";
    rawfp.ws = "7";
    rawfp.df = false;
    processor->push(rawfp);
    TcpFingerprint f110005(rawfp);

    rawfp.fpid = 120001;
    rawfp.fp_type = 11;
    rawfp.fpuuid = "12345678-1234-1234-1234-123456789015";
    rawfp.ttl = 64;
    rawfp.tcp_window = "14400";
    rawfp.mss = "X";
    rawfp.id = "X";
    rawfp.topts = "2 4 8 3";
    rawfp.ws = "7";
    rawfp.df = false;
    processor->push(rawfp);
    TcpFingerprint f120001(rawfp);

    rawfp.fpid = 2;
    rawfp.fp_type = 1;
    rawfp.fpuuid = "12345678-1234-1234-1234-123456789016";
    rawfp.ttl = 64;
    rawfp.tcp_window = "2144 5040-5840";
    rawfp.mss = "X";
    rawfp.id = "X";
    rawfp.topts = "2";
    rawfp.ws = "0-1";
    rawfp.df = false;
    processor->push(rawfp);
    TcpFingerprint f2(rawfp);

    // Testing the insertion case where tcp window is not range
    rawfp.fpid = 1234;
    rawfp.fp_type = 1;
    rawfp.tcp_window = "SYN";
    CHECK( true == processor->push(rawfp) );

    // Testing the insertion failure for duplicate fpid
    rawfp.fp_type = 2;
    CHECK( false == processor->push(rawfp) );

    processor->make_tcp_fp_tables(TcpFpProcessor::TCP_FP_MODE::SERVER);
    processor->make_tcp_fp_tables(TcpFpProcessor::TCP_FP_MODE::CLIENT);

    // match time
    uint8_t ttl = 64;
    TcpFpProcessor::TCP_FP_MODE mode = TcpFpProcessor::TCP_FP_MODE::SERVER;

    // key that matches f_110005 - server side
    uint8_t syn_tcpopts[] = {0, 0, 0, 0};
    FpTcpKey key;
    key.synmss = 1;
    key.num_syn_tcpopts = 4;
    key.syn_tcpopts = syn_tcpopts;
    key.syn_timestamp = 1;
    key.tcp_window = 5750;
    key.mss = 4;
    key.ws = 7;
    key.mss_pos = 0;           // MAXSEG = 2 in position 0
    key.sackok_pos = 1;        // SACKOK = 4 in position 1
    key.timestamp_pos = 2;     // TIMESTAMP = 8 in position 2
    key.ws_pos = 3;            // WSCALE = 3 in position 3
    key.df = false;
    key.isIpv6 = true;
    syn_tcpopts[key.mss_pos] = (uint8_t) tcp::TcpOptCode::MAXSEG;
    syn_tcpopts[key.timestamp_pos] = (uint8_t) tcp::TcpOptCode::TIMESTAMP;
    syn_tcpopts[key.sackok_pos] = (uint8_t) tcp::TcpOptCode::SACKOK;
    syn_tcpopts[key.ws_pos] = (uint8_t) tcp::TcpOptCode::WSCALE;

    const TcpFingerprint* tfp = processor->get_tcp_fp(key, ttl, mode);
    CHECK( (tfp && *tfp == f110005) );

    // as above, except don't set timestamp option 2 4 8 3
    key.syn_timestamp = 0;
    key.mss_pos = 0;           // MAXSEG = 2 in position 0
    key.sackok_pos = 1;        // SACKOK = 4 in position 1
    key.ws_pos = 2;            // WSCALE = 3 in position 2
    key.num_syn_tcpopts = 3;
    syn_tcpopts[key.mss_pos] = (uint8_t) tcp::TcpOptCode::MAXSEG;
    syn_tcpopts[key.sackok_pos] = (uint8_t) tcp::TcpOptCode::SACKOK;
    syn_tcpopts[key.ws_pos] = (uint8_t) tcp::TcpOptCode::WSCALE;

    tfp = processor->get_tcp_fp(key, ttl, mode);
    CHECK( (tfp && *tfp == f110005) );

    // now match something on the client side
    mode = TcpFpProcessor::TCP_FP_MODE::CLIENT;

    // match f_30962 - client side
    key.synmss = 1;
    key.num_syn_tcpopts = 4;
    key.syn_tcpopts = syn_tcpopts;
    key.syn_timestamp = 1;
    key.tcp_window = 1;        // fp tcp_window = -1 gets interpreted as 0-1
    key.mss = 4;
    key.ws = 8;
    key.mss_pos = 0;           // MAXSEG = 2 in position 0
    key.sackok_pos = 1;        // SACKOK = 4 in position 1
    key.timestamp_pos = 2;     // TIMESTAMP = 8 in position 2
    key.ws_pos = 3;            // WSCALE = 3 in position 3
    key.df = true;
    key.isIpv6 = false;
    syn_tcpopts[key.mss_pos] = (uint8_t) tcp::TcpOptCode::MAXSEG;
    syn_tcpopts[key.timestamp_pos] = (uint8_t) tcp::TcpOptCode::TIMESTAMP;
    syn_tcpopts[key.sackok_pos] = (uint8_t) tcp::TcpOptCode::SACKOK;
    syn_tcpopts[key.ws_pos] = (uint8_t) tcp::TcpOptCode::WSCALE;

    tfp = processor->get_tcp_fp(key, ttl, mode);
    CHECK( (tfp && *tfp == f30962) );

    // again, with no ws
    key.ws_pos = -1;
    key.num_syn_tcpopts = 3;
    tfp = processor->get_tcp_fp(key, ttl, mode);
    CHECK(tfp == nullptr);

    delete processor;
    set_tcp_fp_processor(nullptr);
}

TEST_CASE("is_mss_good", "[rna_fingerprint_tcp]")
{
    vector<FpElement> tfp_mss;
    FpTcpKey key;

    // Testing SYN_MATCH case
    tfp_mss.emplace_back(FpElement("SYN-0"));
    tfp_mss.emplace_back(FpElement("SYN-1"));
    key.synmss = 1;
    key.mss = 4;
    CHECK( is_mss_good(key, tfp_mss) == false );

    key.synmss = 1;
    key.mss = 1;
    CHECK( is_mss_good(key, tfp_mss) == true );

    // Testing out of range case
    tfp_mss.clear();
    tfp_mss.emplace_back(FpElement("5"));
    CHECK( is_mss_good(key, tfp_mss) == false );

    // Testing default case
    tfp_mss.clear();
    tfp_mss.emplace_back(FpElement("R"));
    CHECK( is_mss_good(key, tfp_mss) == false );
}

TEST_CASE("is_ws_good", "[rna_fingerprint_tcp]")
{
    FpTcpKey key;
    key.ws_pos = 1;
    key.ws = 2;
    vector<FpElement> tfp_ws;

    // Testing outside the range case
    tfp_ws.emplace_back(FpElement("-1"));
    CHECK( is_ws_good(key, tfp_ws) == false );

    // Testing don't care case
    tfp_ws.clear();
    tfp_ws.emplace_back(FpElement("X"));
    CHECK( is_ws_good(key, tfp_ws) == true );

    // Testing default case
    tfp_ws.clear();
    tfp_ws.emplace_back(FpElement("TS"));
    CHECK( is_ws_good(key, tfp_ws) == false );
}

TEST_CASE("is_option_good", "[rna_fingerprint_tcp]")
{
    int optpos = 1, fp_optpos = 1;
    uint8_t optorder[] = { (uint8_t) tcp::TcpOptCode::WSCALE };
    uint8_t fp_optorder[] = { (uint8_t) tcp::TcpOptCode::MAXSEG };

    // Testing the case when option values are different
    CHECK( is_option_good(optpos, fp_optpos, optorder, fp_optorder) == false );
}

TEST_CASE("is_ts_good", "[rna_fingerprint_tcp]")
{
    vector<FpElement> topts;
    uint8_t optorder[4], fp_optorder[4];
    int optpos = 0;
    FpTcpKey key;

    // Testing SYN timestamp
    key.syn_timestamp = 123456789;
    CHECK( is_ts_good(key, topts, optpos, optorder, fp_optorder) == false );

    // Testing option code without timestamp
    uint8_t syn_tcpopts[] = {0, 0, 0, 0};
    key.syn_tcpopts = syn_tcpopts;
    key.num_syn_tcpopts = 4;
    key.syn_timestamp = 0;
    CHECK( is_ts_good(key, topts, optpos, optorder, fp_optorder) == false );

    // Testing option code with timestamp, but mismatched position
    key.syn_tcpopts[0] = (uint8_t) tcp::TcpOptCode::TIMESTAMP;
    FpElement fpe("X");
    fpe.d.value = 0;
    topts.emplace_back(fpe);
    CHECK( is_ts_good(key, topts, optpos, optorder, fp_optorder) == false );

    // Testing option code with timestamp, matched position, but mismatched order
    optpos = 1;
    optorder[0] = (uint8_t) tcp::TcpOptCode::MAXSEG;
    CHECK( is_ts_good(key, topts, optpos, optorder, fp_optorder) == false );

    // Testing option code with timestamp, matched position, and matched order
    optorder[0] = (uint8_t) tcp::TcpOptCode::EOL;
    CHECK( is_ts_good(key, topts, optpos, optorder, fp_optorder) == true );
}

TEST_CASE("get_tcp_option", "[rna_fingerprint_tcp]")
{
    // The following hex bytes are dumped from a packet of a random pcap with flow like this:
    // IP 192.168.0.89:9012 -> p3nlh044.shr.prod.phx3.secureserver.net.http
    // Flag SYN, win 8192, length 0, option 0
    // The bytes are modified just enough to test the desired case for the option flag.
    uint8_t cooked_pkt[] = "\x00\x21\x91\x01\xb2\x48\xaa\x00\x04\x00\x0a\x04\x08\x00\x45"
        "\x00\x00\x28\x00\x01\x00\x00\x40\x06\x88\x96\xc0\xa8\x00\x59\x48\xa7\xe8\x90\x23"
        "\x34\x00\x50\x00\x00\x23\x5a\x00\x00\x00\x00\x50\x02\x20\x00\x56\xcb\x00\x00\x00";
    Packet p(false);
    p.pkt = cooked_pkt;
    p.ptrs.tcph = ( const tcp::TCPHdr* )( cooked_pkt + 34 );
    p.num_layers = 1;
    Layer cooked_layer;
    cooked_layer.start = cooked_pkt + 34;
    cooked_layer.length = 21; // TCP_MIN_HEADER_LEN + 1
    auto saved_layers = p.layers;
    p.layers = &cooked_layer;
    int pos;

    // Check the default case when the desired option does not match
    CHECK( -1 == get_tcp_option(&p, tcp::TcpOptCode::EOL, pos) );

    // Check the case when NOP option is matched
    cooked_pkt[54] = 1; // 34 + TCP_MIN_HEADER_LEN = 54
    CHECK( get_tcp_option(&p, tcp::TcpOptCode::NOP, pos) == 1 );

    p.layers = saved_layers;
}

#endif
