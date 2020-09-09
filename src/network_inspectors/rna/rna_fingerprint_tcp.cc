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
#include "protocols/packet.h"
#include "protocols/tcp.h"
#include "protocols/tcp_options.h"

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

void TcpFpProcessor::push(const TcpFingerprint& tfp)
{
    const auto& result = tcp_fps.emplace(make_pair(tfp.fpid, tfp));
    if (!result.second)
        WarningMessage("TcpFpProcessor: ignoring previously seen fingerprint id: %d\n", tfp.fpid);

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
            FpFingerprint::FpType::FINGERPRINT_TYPE_SERVER6 :
            FpFingerprint::FpType::FINGERPRINT_TYPE_SERVER;
    }
    else if (mode == TCP_FP_MODE::CLIENT)
    {
        fptable = table_tcp_client;
        fptype = key.isIpv6 ?
            FpFingerprint::FpType::FINGERPRINT_TYPE_CLIENT6 :
            FpFingerprint::FpType::FINGERPRINT_TYPE_CLIENT;
    }
    else
    {
        ErrorMessage("TcpFpProcessor::get_tcp_fingerprint(): Invalid mode - %d", mode);
        return nullptr;
    }

    const auto& tfpvec = fptable[key.tcp_window];
    for (const auto& tfp : tfpvec)
    {
        if (tfp->fp_type != fptype )
            continue;   // tfp

        for (const auto& fpe_mss : tfp->mss)
        {
            switch (fpe_mss.type)
            {
            case FpElementType::RANGE:
                if (key.mss >= fpe_mss.d.range.min &&
                    key.mss <= fpe_mss.d.range.max)
                {
                    goto mssgood;
                }
                break;
            case FpElementType::SYN_MATCH:
                //if synmss is negative, it means that client didn't send MSS option
                if ((key.synmss  >= 0)
                    && ((!fpe_mss.d.value && key.mss <= key.synmss)
                        || (fpe_mss.d.value && ((key.synmss < fpe_mss.d.value && key.mss <= key.synmss)
                        || (key.synmss >= fpe_mss.d.value && key.mss <= fpe_mss.d.value)))))
                {
                    goto mssgood;
                }
                break;
            case FpElementType::DONT_CARE:
            case FpElementType::SYNTS:
                goto mssgood;
            default:
                break;
            }
        }
        continue;  // tfp

    mssgood:
        if (key.df == tfp->df &&
            ttl <= tfp->ttl &&
            (tfp->ttl < MAXIMUM_FP_HOPS || ttl >= (tfp->ttl - MAXIMUM_FP_HOPS)))
        {
            if (key.ws_pos >= 0)
            {
                for (const auto& fpe_ws : tfp->ws)
                {
                    switch (fpe_ws.type)
                    {
                    case FpElementType::RANGE:
                        if (key.ws >= fpe_ws.d.range.min &&
                            key.ws <= fpe_ws.d.range.max)
                        {
                            goto wsgood;
                        }
                        break;
                    case FpElementType::DONT_CARE:
                        goto wsgood;
                    default:
                        break;
                    }
                }
                continue;  // tfp
            }

        wsgood:
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
                if (optpos != fp_optpos) goto check_ts;

                for (i=0; i<optpos; i++)
                {
                    if (optorder[i] != fp_optorder[i]) goto check_ts;
                }
                return tfp;

            check_ts:
                //number and type of options didn't match between SYN and fingerprint.
                //Ignore Timestamp option if present in SYN. Remaining processing is
                //the same as the block above.
                for (i=0; i<key.num_syn_tcpopts; i++)
                {
                    if (key.syn_tcpopts[i] == (uint8_t) tcp::TcpOptCode::TIMESTAMP)
                    {
                        break;
                    }
                }
                if (i >= key.num_syn_tcpopts || key.syn_timestamp)
                    continue;    // tfp

                fp_optpos = 0;
                for (const auto& fpe_topts : tfp->topts)
                {
                    for (i=0; i<key.num_syn_tcpopts; i++)
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
                    continue;   // ftp

                for (i=0; i<optpos; i++)
                {
                    if (optorder[i] != fp_optorder[i])
                        continue; // tfp
                }
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
    if (maxops < 0 || TCP_OPTLENMAX < maxops)
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
    FpTcpKey fpk;
    bool mssOptionPresent = false;

    bzero(&fpk, sizeof(FpTcpKey));

    if (p->is_ip6())
        fpk.isIpv6 = 1;

    /* build a key for the lookup */
    fpk.df = p->ptrs.dont_fragment();
    fpk.tcp_window = p->ptrs.tcph->win();

    fpk.mss = get_tcp_option(p, tcp::TcpOptCode::MAXSEG, fpk.mss_pos);
    if (fpk.mss_pos >= 0)
    {
        get_tcp_option(p, tcp::TcpOptCode::SACKOK, fpk.sackok_pos);
        fpk.ws = get_tcp_option(p, tcp::TcpOptCode::WSCALE, fpk.ws_pos);
        get_tcp_option(p, tcp::TcpOptCode::TIMESTAMP, fpk.timestamp_pos);
        mssOptionPresent = 1;
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

size_t RNAFlow::size_of()
{
    return sizeof(*this);
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
    rawfp.df = 1;

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
    rawfp.df = 1;

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
    rawfp.df = 1;
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
    rawfp.df = 1;
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
    rawfp.df = 0;
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
    rawfp.df = 0;
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
    rawfp.df = 0;
    processor->push(rawfp);
    TcpFingerprint f2(rawfp);

    processor->make_tcp_fp_tables(TcpFpProcessor::TCP_FP_MODE::SERVER);
    processor->make_tcp_fp_tables(TcpFpProcessor::TCP_FP_MODE::CLIENT);

    // match time
    const TcpFingerprint* tfp;
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
    key.df = 0;
    key.isIpv6 = 1;
    syn_tcpopts[key.mss_pos] = (uint8_t) tcp::TcpOptCode::MAXSEG;
    syn_tcpopts[key.timestamp_pos] = (uint8_t) tcp::TcpOptCode::TIMESTAMP;
    syn_tcpopts[key.sackok_pos] = (uint8_t) tcp::TcpOptCode::SACKOK;
    syn_tcpopts[key.ws_pos] = (uint8_t) tcp::TcpOptCode::WSCALE;

    tfp = processor->get_tcp_fp(key, ttl, mode);
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
    key.df = 1;
    key.isIpv6 = 0;
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

#endif
