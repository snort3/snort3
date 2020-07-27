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

// rna_fingerprint_tcp.h author Silviu Minut <sminut@cisco.com>

#ifndef RNA_FINGERPRINT_TCP_H
#define RNA_FINGERPRINT_TCP_H

#include <list>
#include <vector>

#include "main/snort_types.h"
#include "protocols/packet.h"

#include "rna_fingerprint.h"

namespace snort
{

enum FpElementType
{
    RANGE=1,
    INCREMENT,
    SYN_MATCH,
    RANDOM,
    DONT_CARE,
    SYNTS
};

class FpElement
{
public:
    FpElementType type;
    union
    {
        int value;
        struct
        {
            int min;
            int max;
        } range;
    } d;
};

class FpTcpFingerprint : public FpFingerprint
{
public:

    std::vector<FpElement> tcp_window;
    std::vector<FpElement> mss;
    std::vector<FpElement> id;
    std::vector<FpElement> topts;
    std::vector<FpElement> ws;
    char df;
};

class TcpFpProcessor
{
public:

    enum TCP_FP_MODE { SERVER, CLIENT };

    typedef std::list<snort::FpTcpFingerprint>::iterator Iter_t;

    SO_PUBLIC void push(const std::vector<snort::FpTcpFingerprint>&, TCP_FP_MODE);


private:

    // table_tcp_xxx[i] contains all fingerprints whose tcp window range
    // contains i
    std::vector<const snort::FpTcpFingerprint*> table_tcp_server[snort::MAX_PORTS];
    std::vector<const snort::FpTcpFingerprint*> table_tcp_client[snort::MAX_PORTS];
};

SO_PUBLIC TcpFpProcessor* get_tcp_fp_processor();
}

#endif
