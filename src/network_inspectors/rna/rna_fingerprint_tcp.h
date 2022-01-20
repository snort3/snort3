//--------------------------------------------------------------------------
// Copyright (C) 2020-2022 Cisco and/or its affiliates. All rights reserved.
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

// rna_fingerprint_tcp.h author Silviu Minut <sminut@cisco.com>

#ifndef RNA_FINGERPRINT_TCP_H
#define RNA_FINGERPRINT_TCP_H

#include <mutex>
#include <unordered_map>
#include <vector>

#include "main/snort_types.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"
#include "sfip/sf_ip.h"

#include "rna_fingerprint.h"

class RNAFlow;

namespace snort
{

class SO_PUBLIC TcpFingerprint : public FpFingerprint
{
public:

    TcpFingerprint() = default;
    TcpFingerprint(const RawFingerprint& rfp);

    std::vector<FpElement> tcp_window;
    std::vector<FpElement> mss;
    std::vector<FpElement> id;
    std::vector<FpElement> topts;
    std::vector<FpElement> ws;
    bool df = false;

    void clear() override
    {
        FpFingerprint::clear();
        tcp_window.clear();
        mss.clear();
        id.clear();
        topts.clear();
        ws.clear();
        df = false;
    }

    bool operator==(const TcpFingerprint& y) const;
};

struct FpTcpKey
{
    int synmss;
    uint8_t *syn_tcpopts;
    int num_syn_tcpopts;
    int syn_timestamp;

    int tcp_window;
    int mss;
    int ws;

    int mss_pos;
    int ws_pos;
    int sackok_pos;
    int timestamp_pos;

    bool df;
    bool isIpv6;
};

class SO_PUBLIC TcpFpProcessor
{
public:

    typedef std::unordered_map<uint32_t, TcpFingerprint> TcpFpContainer;

    enum TCP_FP_MODE { SERVER, CLIENT };

    bool push(const TcpFingerprint&);

    void make_tcp_fp_tables(TCP_FP_MODE);

    const TcpFingerprint* get_tcp_fp(const FpTcpKey&, uint8_t, TCP_FP_MODE) const;

    const TcpFingerprint* get(const Packet*, RNAFlow*) const;

    const TcpFingerprint* get(uint32_t fpid) const
    {
        auto it = tcp_fps.find(fpid);
        return it != tcp_fps.end() ? &it->second : nullptr;
    }

    const TcpFpContainer& get_tcp_fps() const
    { return tcp_fps; }

private:

    // underlying container for input fingerprints
    TcpFpContainer tcp_fps;

    // table_tcp_xxx[i] contains pointers into tcp_fps to all fingerprints
    // whose tcp window range contains i
    static constexpr uint32_t table_size = TCP_MAXWIN + 1;
    std::vector<const snort::TcpFingerprint*> table_tcp_server[table_size];
    std::vector<const snort::TcpFingerprint*> table_tcp_client[table_size];
};

}

snort::TcpFpProcessor* get_tcp_fp_processor();
SO_PUBLIC void set_tcp_fp_processor(snort::TcpFpProcessor*);

struct FpFingerprintState
{
    int initial_mss = -1;
    int timestamp = -1;
    int numopts = -1;
    uint8_t tcpopts[4];
    time_t timeout = -1;

    bool set(const snort::Packet*);
};

#endif
