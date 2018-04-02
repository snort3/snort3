//--------------------------------------------------------------------------
// Copyright (C) 2017-2018 Cisco and/or its affiliates. All rights reserved.
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
// ftpdata_splitter.cc author davis mcpherson <davmcphe@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ftpdata_splitter.h"

#include "file_api/file_flows.h"
#include "flow/session.h"
#include "stream/stream.h"

#include "ftpp_si.h"

using namespace snort;

void FtpDataSplitter::restart_scan()
{
    bytes = segs = 0;
}

static void set_ftp_flush_flag(Flow* flow)
{
    FtpDataFlowData* fdfd = (FtpDataFlowData*)flow->get_flow_data(FtpDataFlowData::inspector_id);
    if ( fdfd )
        fdfd->session.packet_flags |= FTPDATA_FLG_FLUSH;
}

StreamSplitter::Status FtpDataSplitter::scan(Flow* flow, const uint8_t*, uint32_t len,
    uint32_t, uint32_t* fp)
{
    if ( len )
    {
        if(expected_seg_size == 0)
        {
            // FIXIT-M: Can we do better than this guess if no MSS is specified?
            //          Malware detection won't work if expected_seg_size
            //          doesn't match the payload lengths on packets before
            //          the last packet.
            expected_seg_size = 1448;

            if(flow->session and flow->pkt_type == PktType::TCP)
            {
                expected_seg_size = Stream::get_mss(flow, to_server());
                uint8_t tcp_options_len = Stream::get_tcp_options_len(flow, to_server());
                if(expected_seg_size > tcp_options_len)
                    expected_seg_size -= tcp_options_len;
            }
        }

        if ( len != expected_seg_size )
        {
            // Treat this as the last packet of the FTP data transfer.
            set_ftp_flush_flag(flow);
            expected_seg_size = len;
            restart_scan();
            *fp = len;
            return FLUSH;
        }
        else
        {
            segs++;
            bytes += len;
        }

        if ( segs >= 2 && bytes >= min )
        {
            restart_scan();
            *fp = len;
            return FLUSH;
        }
    }

    return SEARCH;
}

bool FtpDataSplitter::finish(Flow* flow)
{
    bool status = true;

    if ( bytes == 0 )
    {
        status = false;

        FtpDataFlowData* fdfd = (FtpDataFlowData*)flow->get_flow_data(FtpDataFlowData::inspector_id);
        if ( fdfd )
        {
            if ( !fdfd->eof_handled )
            {
                initFilePosition(&fdfd->session.position, get_file_processed_size(flow));
                finalFilePosition(&fdfd->session.position);
            }

            FileFlows* file_flows = FileFlows::get_file_flows(flow);
            if ( file_flows )
                file_flows->file_process(nullptr, 0, SNORT_FILE_END, to_server(), 0);
        }
    }

    return status;
}

