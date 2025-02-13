//--------------------------------------------------------------------------
// Copyright (C) 2017-2025 Cisco and/or its affiliates. All rights reserved.
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

#include "detection/detection_engine.h"
#include "file_api/file_flows.h"
#include "flow/session.h"
#include "packet_io/active.h"
#include "protocols/tcp.h"
#include "stream/stream.h"

#include "ftpp_si.h"

using namespace snort;

void FtpDataSplitter::restart_scan()
{
    bytes = segs = 0;
}

StreamSplitter::Status FtpDataSplitter::scan(Packet* pkt, const uint8_t*, uint32_t len,
    uint32_t flags, uint32_t* fp)
{
    Flow* flow = pkt->flow;
    assert(flow);

    FtpDataFlowData* fdfd = nullptr;

    if ( len )
    {
        if(expected_seg_size == 0)
        {
            expected_seg_size = 1448;

            if(flow->session and flow->pkt_type == PktType::TCP)
            {
                expected_seg_size = Stream::get_mss(flow, to_server());
                uint8_t tcp_options_len = Stream::get_tcp_options_len(flow, to_server());
                if(expected_seg_size > tcp_options_len)
                    expected_seg_size -= tcp_options_len;
            }
        }
        segs++;
        bytes += len;
        if ( len != expected_seg_size )
        {
            fdfd = (FtpDataFlowData*)flow->get_flow_data(FtpDataFlowData::inspector_id);
            if (!fdfd)
                return SEARCH;

            ftstats.total_packets_mss_changed++;
            fdfd->session.mss_changed = true;
            expected_seg_size = len;

            if (!flow->assistant_gadget && pkt->ptrs.tcph and !pkt->ptrs.tcph->is_fin())
            {
                // set flag for signature calculation in case this is the last packet
                fdfd->session.packet_flags |= FTPDATA_FLG_FLUSH;
                pkt->active->hold_packet(pkt);
                return SEARCH;
            }
        }

        if (flow->assistant_gadget && (flags & FTPDATA_FLG_FLUSH))
        {
            fdfd = (FtpDataFlowData*)flow->get_flow_data(FtpDataFlowData::inspector_id);
            if (!fdfd)
                return SEARCH;

            fdfd->session.packet_flags |= FTPDATA_FLG_FLUSH;
            pkt->active->hold_packet(pkt);
            return SEARCH;
        }
    }

    if ((segs >= 2 and bytes >= min) or (pkt->ptrs.tcph and pkt->ptrs.tcph->is_fin()))
    {
        fdfd = (FtpDataFlowData*)flow->get_flow_data(FtpDataFlowData::inspector_id);
        if (!fdfd)
            return SEARCH;

        restart_scan();
        *fp = len;
        // avoid unnecessary signature calc by clearing the flag set by detained packet
        if (fdfd->session.packet_flags & FTPDATA_FLG_FLUSH)
            fdfd->session.packet_flags &= ~FTPDATA_FLG_FLUSH;
        return FLUSH;
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
            {
                file_flows->file_process(DetectionEngine::get_current_packet(),
                    nullptr, 0, SNORT_FILE_END, to_server(), fdfd->session.path_hash);
            }
        }
    }

    return status;
}

