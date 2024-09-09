//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2004-2013 Sourcefire, Inc.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ftp_data.h"

#include <memory>
#include <string>

#include "detection/detection_engine.h"
#include "file_api/file_flows.h"
#include "file_api/file_service.h"
#include "packet_io/active.h"
#include "packet_io/packet_tracer.h"
#include "parser/parse_rule.h"
#include "profiler/profiler.h"
#include "protocols/tcp.h"
#include "pub_sub/opportunistic_tls_event.h"
#include "stream/stream.h"
#include "utils/util.h"

#include "ft_main.h"
#include "ftpp_si.h"
#include "ftpdata_splitter.h"

using namespace snort;

#define s_help \
    "FTP data channel handler"

static const char* const fd_svc_name = "ftp-data";

static THREAD_LOCAL ProfileStats ftpdataPerfStats;
static THREAD_LOCAL SimpleStats fdstats;

//-------------------------------------------------------------------------
// implementation stuff
//-------------------------------------------------------------------------

static void FTPDataProcess(
    Packet* p, FTP_DATA_SESSION* data_ssn, const uint8_t* file_data, uint16_t data_length)
{
    int status;

    set_file_data(p->data, p->dsize, data_ssn->path_hash);

    if (data_ssn->packet_flags & FTPDATA_FLG_REST)
    {
        p->active->block_again();
        p->active->set_drop_reason("ftp");
        if (PacketTracer::is_active())
            PacketTracer::log("FTP: session reset, drop\n");
        return;
    }

    FileFlows* file_flows = FileFlows::get_file_flows(p->flow);
    if (!file_flows)
        return;

    if (data_ssn->packet_flags & FTPDATA_FLG_FLUSH)
    {
        file_flows->set_sig_gen_state(true);
        data_ssn->packet_flags &= ~FTPDATA_FLG_FLUSH;
    }
    else
        file_flows->set_sig_gen_state(false);

    status = file_flows->file_process(p, file_data, data_length,
        data_ssn->position, data_ssn->direction, data_ssn->path_hash);

    if (p->active->packet_force_dropped())
    {
        FtpFlowData* fd = (FtpFlowData*)Stream::get_flow_data(
                            &data_ssn->ftp_key, FtpFlowData::inspector_id);

        FTP_SESSION* ftp_ssn = fd ? &fd->session : nullptr;

        if (PROTO_IS_FTP(ftp_ssn))
            ftp_ssn->flags |= FTP_FLG_MALWARE;
    }

    /* Filename needs to be set AFTER the first call to file_process( ) */
    if (data_ssn->filename && !(data_ssn->packet_flags & FTPDATA_FLG_FILENAME_SET))
    {
        file_flows->set_file_name((uint8_t*)data_ssn->filename, data_ssn->file_xfer_info);
        data_ssn->packet_flags |= FTPDATA_FLG_FILENAME_SET;
    }

    // Ignore the rest of this transfer if file processing is complete
    // and status is returned false (eg sig not enabled, sig depth exceeded etc)
    // and no IPS rules are configured.
    if (!status)
    {
        IpsPolicy* empty_policy = snort::get_empty_ips_policy(p->context->conf);
        if (empty_policy->policy_id == p->flow->ips_policy_id)
        {
            if (PacketTracer::is_active())
                PacketTracer::log("Whitelisting Flow: FTP data\n");
            p->flow->set_ignore_direction(SSN_DIR_BOTH);
        }
    }
}

static int SnortFTPData(Packet* p)
{
    if (!p->flow)
        return -1;

    FtpDataFlowData* fdfd = (FtpDataFlowData*)
        p->flow->get_flow_data(FtpDataFlowData::inspector_id);

    FTP_DATA_SESSION* data_ssn = fdfd ? &fdfd->session : nullptr;

    if (!data_ssn or (data_ssn->packet_flags & FTPDATA_FLG_STOP))
        return 0;

    assert(PROTO_IS_FTP_DATA(data_ssn));

    //  bail if we have not rebuilt the stream yet.
    if (!(p->packet_flags & PKT_REBUILT_STREAM))
        return 0;

    if (data_ssn->file_xfer_info == FTPP_FILE_UNKNOWN)
    {
        /* FTP-Data session is in limbo, we need to lookup the control session
         * to figure out what to do. */

        FtpFlowData* ffd = (FtpFlowData*)Stream::get_flow_data(
            &data_ssn->ftp_key, FtpFlowData::inspector_id);

        FTP_SESSION* ftp_ssn = ffd ? &ffd->session : nullptr;

        if (!PROTO_IS_FTP(ftp_ssn))
        {
            if (data_ssn->data_chan)
                p->flow->set_ignore_direction(SSN_DIR_BOTH);

            return -2;
        }

        switch (ftp_ssn->file_xfer_info)
        {
        case FTPP_FILE_UNKNOWN:
            /* Keep waiting */
            break;

        case FTPP_FILE_IGNORE:
            /* This wasn't a file transfer; ignore it */
            if (data_ssn->data_chan)
                p->flow->set_ignore_direction(SSN_DIR_BOTH);
            return 0;

        default:
            /* A file transfer was detected. */
            data_ssn->direction = ftp_ssn->data_xfer_dir;
            data_ssn->file_xfer_info = ftp_ssn->file_xfer_info;
            ftp_ssn->file_xfer_info  = 0;
            data_ssn->filename  = ftp_ssn->filename;
            data_ssn->path_hash = ftp_ssn->path_hash;
            ftp_ssn->filename   = nullptr;
            ftp_ssn->path_hash = 0;
            break;
        }
    }

    if (!FTPDataDirection(p, data_ssn))
        return 0;

    if (isFileEnd(data_ssn->position))
    {
        data_ssn->packet_flags |= FTPDATA_FLG_STOP;
    }
    else
    {
        initFilePosition(&data_ssn->position, get_file_processed_size(p->flow));
    }

    FTPDataProcess(p, data_ssn, p->data, p->dsize);
    return 0;
}

//-------------------------------------------------------------------------
// flow data stuff
//-------------------------------------------------------------------------

unsigned FtpDataFlowData::inspector_id = 0;

FtpDataFlowData::FtpDataFlowData(Packet* p) : FlowData(inspector_id)
{
    memset(&session, 0, sizeof(session));

    session.ft_ssn.proto = FTPP_SI_PROTO_FTP_DATA;
    Stream::populate_flow_key(p, &session.ftp_key);
    if (p->flow)
    {
        session.ftp_key.pkt_type = p->flow->pkt_type;
        session.ftp_key.ip_protocol = p->flow->ip_proto;
    }
}

FtpDataFlowData::~FtpDataFlowData()
{
    if (session.filename)
        snort_free(session.filename);
}

void FtpDataFlowData::handle_expected(Packet* p)
{
    if (!p->flow->service)
    {
        p->flow->set_service(p, fd_svc_name);

        FtpDataFlowData* fd =
            (FtpDataFlowData*)p->flow->get_flow_data(FtpDataFlowData::inspector_id);
        if (fd and fd->in_tls)
        {
            OpportunisticTlsEvent evt(p, fd_svc_name);
            DataBus::publish(intrinsic_pub_id, IntrinsicEventIds::OPPORTUNISTIC_TLS, evt, p->flow);
        }
        else
            DataBus::publish(intrinsic_pub_id, IntrinsicEventIds::SSL_SEARCH_ABANDONED, p);
    }
}

void FtpDataFlowData::handle_eof(Packet* p)
{
    FTP_DATA_SESSION* data_ssn = &session;

    if (!PROTO_IS_FTP_DATA(data_ssn) || !FTPDataDirection(p, data_ssn))
        return;

    initFilePosition(&data_ssn->position, get_file_processed_size(p->flow));
    finalFilePosition(&data_ssn->position);
    eof_handled = true;

    if (data_ssn->mss_changed)
        ftstats.total_sessions_mss_changed++;
}

const PegInfo* FtpDataModule::get_pegs() const
{ return simple_pegs; }

PegCount* FtpDataModule::get_counts() const
{ return (PegCount*)&fdstats; }

ProfileStats* FtpDataModule::get_profile() const
{ return &ftpdataPerfStats; }

void FtpData::eval(Packet* p)
{
    // cppcheck-suppress unreadVariable
    Profile profile(ftpdataPerfStats);

    // precondition - what we registered for
    assert(p->has_tcp_data());

    SnortFTPData(p);
    ++fdstats.total_packets;
}

StreamSplitter* FtpData::get_splitter(bool to_server)
{
    return new FtpDataSplitter(to_server);
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new FtpDataModule; }

static void mod_dtor(Module* m)
{ delete m; }

static void fd_init()
{
    FtpDataFlowData::init();
}

static Inspector* fd_ctor(Module*)
{
    return new FtpData;
}

static void fd_dtor(Inspector* p)
{
    delete p;
}

static const char* fd_bufs[] =
{
    "file_data",
    nullptr
};

// exported in ftp.cc
const InspectApi fd_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        FTP_DATA_NAME,
        s_help,
        mod_ctor,
        mod_dtor
    },
    IT_SERVICE,
    PROTO_BIT__PDU,
    fd_bufs,
    fd_svc_name,
    fd_init,
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    fd_ctor,
    fd_dtor,
    nullptr, // ssn
    nullptr  // reset
};

