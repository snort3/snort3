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

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;
using namespace std;

static TcpFpProcessor tcp_fp_processor;

namespace snort
{

TcpFpProcessor* get_tcp_fp_processor()
{
    return &tcp_fp_processor;
}

void TcpFpProcessor::push(const vector<FpTcpFingerprint>& fplist, TCP_FP_MODE mode)
{
    vector<const FpTcpFingerprint*>* fptable = (mode == TCP_FP_MODE::SERVER ?
        table_tcp_server : table_tcp_client);

    for (const auto& tfp : fplist)
    {
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

}

#ifdef UNIT_TEST
TEST_CASE("get_tcp_fp_processor", "[tcp_processor]")
{
    vector<FpTcpFingerprint> fplist;
    tcp_fp_processor.push(fplist, TcpFpProcessor::TCP_FP_MODE::SERVER);

    snort::TcpFpProcessor* tfp = snort::get_tcp_fp_processor();
    CHECK(tfp == &tcp_fp_processor);
}

#endif
