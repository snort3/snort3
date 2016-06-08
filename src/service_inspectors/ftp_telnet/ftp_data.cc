//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

#include "ftp_data.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ftp_module.h"
#include "ftpp_si.h"

#include "detection/detection_util.h"
#include "file_api/file_service.h"
#include "file_api/file_flows.h"
#include "profiler/profiler.h"
#include "utils/util.h"

#define s_name "ftp_data"

#define s_help \
    "FTP data channel handler"

static THREAD_LOCAL ProfileStats ftpdataPerfStats;
static THREAD_LOCAL SimpleStats fdstats;

//-------------------------------------------------------------------------
// implementation stuff
//-------------------------------------------------------------------------

// FIXIT-L seems like file_data should be const pointer.
// Need to root this out and eliminate const-removing casts.
static void FTPDataProcess(
    Packet* p, FTP_DATA_SESSION* data_ssn, uint8_t* file_data, uint16_t data_length)
{
    int status;

    set_file_data((uint8_t*)p->data, p->dsize);

    FileFlows* file_flows = FileFlows::get_file_flows(p->flow);

    if (!file_flows)
        return;

    status = file_flows->file_process(file_data, data_length,
        data_ssn->position, data_ssn->direction);

    /* Filename needs to be set AFTER the first call to file_process( ) */
    if (data_ssn->filename && !(data_ssn->packet_flags & FTPDATA_FLG_FILENAME_SET))
    {
        file_flows->set_file_name((uint8_t*)data_ssn->filename, data_ssn->file_xfer_info);
        data_ssn->packet_flags |= FTPDATA_FLG_FILENAME_SET;
    }

    /* Ignore the rest of this transfer if file processing is complete
     * and preprocessor was configured to ignore ftp-data sessions. */
    if (!status && data_ssn->data_chan)
    {
        p->flow->set_ignore_direction(SSN_DIR_BOTH);
    }
}

static int SnortFTPData(Packet* p)
{
    if (!p->flow)
        return -1;

    FtpDataFlowData* fd = (FtpDataFlowData*)
        p->flow->get_application_data(FtpFlowData::flow_id);

    FTP_DATA_SESSION* data_ssn = fd ? &fd->session : nullptr;

    assert(PROTO_IS_FTP_DATA(data_ssn));

    if ( !data_ssn or (data_ssn->packet_flags & FTPDATA_FLG_STOP) )
        return 0;

    //  bail if we have not rebuilt the stream yet.
    if (!(p->packet_flags & PKT_REBUILT_STREAM))
        return 0;

    if (data_ssn->file_xfer_info == FTPP_FILE_UNKNOWN)
    {
        /* FTP-Data session is in limbo, we need to lookup the control session
         * to figure out what to do. */

        FtpFlowData* fd = (FtpFlowData*)stream.get_application_data_from_key(
            &data_ssn->ftp_key, FtpFlowData::flow_id);

        FTP_SESSION* ftp_ssn = fd ? &fd->session : NULL;

        if (!PROTO_IS_FTP(ftp_ssn))
        {
            DebugMessage(DEBUG_FTPTELNET,
                "FTP-DATA Invalid FTP_SESSION retrieved durring lookup\n");

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
            ftp_ssn->filename   = NULL;
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

    FTPDataProcess(p, data_ssn, (uint8_t*)p->data, p->dsize);
    return 0;
}

//-------------------------------------------------------------------------
// flow data stuff
//-------------------------------------------------------------------------

unsigned FtpDataFlowData::flow_id = 0;

FtpDataFlowData::FtpDataFlowData(Packet* p) : FlowData(flow_id)
{
    memset(&session, 0, sizeof(session));

    session.ft_ssn.proto = FTPP_SI_PROTO_FTP_DATA;
    stream.populate_session_key(p, &session.ftp_key);
}

FtpDataFlowData::~FtpDataFlowData()
{
    if (session.filename)
        snort_free(session.filename);
}

void FtpDataFlowData::handle_eof(Packet* p)
{
    FTP_DATA_SESSION* data_ssn = &session;

    if (!PROTO_IS_FTP_DATA(data_ssn) || !FTPDataDirection(p, data_ssn))
        return;

    initFilePosition(&data_ssn->position, get_file_processed_size(p->flow));
    finalFilePosition(&data_ssn->position);

    stream.flush_request(p);

    if (!(data_ssn->packet_flags & FTPDATA_FLG_STOP))
    {
        data_ssn->packet_flags |= FTPDATA_FLG_STOP;
        FTPDataProcess(p, data_ssn, (uint8_t*)p->data, p->dsize);
    }
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class FtpData : public Inspector
{
public:
    FtpData() { }
    ~FtpData() { }

    void eval(Packet*) override;
};

class FtpDataModule : public Module
{
public:
    FtpDataModule() : Module(s_name, s_help) { }

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    ProfileStats* get_profile() const override;

    bool set(const char*, Value&, SnortConfig*) override
    { return false; }
};

const PegInfo* FtpDataModule::get_pegs() const
{ return simple_pegs; }

PegCount* FtpDataModule::get_counts() const
{ return (PegCount*)&fdstats; }

ProfileStats* FtpDataModule::get_profile() const
{ return &ftpdataPerfStats; }

void FtpData::eval(Packet* p)
{
    Profile profile(ftpdataPerfStats);

    // precondition - what we registered for
    assert(p->has_tcp_data());

    if ( FileService::get_max_file_depth() < 0 )
        return;

    SnortFTPData(p);
    ++fdstats.total_packets;
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
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    IT_SERVICE,
    (uint16_t)PktType::PDU,
    nullptr, // buffers
    "ftp-data",
    fd_init,
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    fd_ctor,
    fd_dtor,
    nullptr, // ssn
    nullptr  // reset
};

