/*
 * Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2004-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "ftp_data.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>

#include "snort_types.h"
#include "snort_debug.h"

#include "ftp_module.h"
#include "ftpp_si.h"
#include "ftpp_ui_config.h"
#include "ftpp_return_codes.h"
#include "ftp_cmd_lookup.h"
#include "ft_main.h"
#include "ftp_parse.h"
#include "ftp_print.h"
#include "ftp_splitter.h"
#include "pp_ftp.h"
#include "profiler.h"

#include "stream/stream_api.h"
#include "file_api/file_api.h"
#include "parser.h"
#include "framework/inspector.h"
#include "framework/plug_data.h"
#include "detection/detection_util.h"
#include "protocols/tcp.h"

static const char* s_name = "ftp_data";

static const char* s_help =
    "FTP data channel handler";

static THREAD_LOCAL ProfileStats ftpdataPerfStats;
static THREAD_LOCAL SimpleStats fdstats;

//-------------------------------------------------------------------------
// implementation stuff
//-------------------------------------------------------------------------

static void FTPDataProcess(Packet *p, FTP_DATA_SESSION *data_ssn)
{
    int status;

    set_file_data((uint8_t *)p->data, p->dsize);

    status = file_api->file_process(p, (uint8_t *)p->data,
        (uint16_t)p->dsize, data_ssn->position, data_ssn->direction, false);

    /* Filename needs to be set AFTER the first call to file_process( ) */
    if (data_ssn->filename && !(data_ssn->packet_flags & FTPDATA_FLG_FILENAME_SET))
    {
        file_api->set_file_name(p->flow,
          (uint8_t *)data_ssn->filename, data_ssn->file_xfer_info);
        data_ssn->packet_flags |= FTPDATA_FLG_FILENAME_SET;
    }

    /* Ignore the rest of this transfer if file processing is complete
     * and preprocessor was configured to ignore ftp-data sessions. */
    if (!status && data_ssn->data_chan)
    {
        stream.set_ignore_direction(p->flow, SSN_DIR_BOTH);
    }
}

static int SnortFTPData(Packet *p)
{
    if (!p->flow)
        return -1;

    FtpDataFlowData* fd = (FtpDataFlowData*)
        p->flow->get_application_data(FtpFlowData::flow_id);

    FTP_DATA_SESSION* data_ssn = fd ? &fd->session : nullptr;

    assert(PROTO_IS_FTP_DATA(data_ssn));

    /* Do this now before splitting the work for rebuilt and raw packets. */
    if ((p->packet_flags & PKT_PDU_TAIL) || (p->ptrs.tcph->th_flags & TH_FIN))
        SetFTPDataEOFDirection(p, data_ssn);

    /*
     * Raw Packet Processing
     */
    if (!(p->packet_flags & PKT_REBUILT_STREAM))
    {
        if (!(data_ssn->packet_flags & FTPDATA_FLG_REASSEMBLY_SET))
        {
            /* Enable Reassembly */
            stream.set_splitter(p->flow, true);
            stream.set_splitter(p->flow, false);

            data_ssn->packet_flags |= FTPDATA_FLG_REASSEMBLY_SET;
        }

        if (data_ssn->file_xfer_info == FTPP_FILE_UNKNOWN)
            return 0;

        if (!FTPDataDirection(p, data_ssn) && FTPDataEOF(data_ssn))
        {
            /* flush any remaining data from transmitter. */
            stream.response_flush_stream(p);

            /* If position is not set to END then no data has been flushed */
            if ((data_ssn->position != SNORT_FILE_END) ||
                (data_ssn->position != SNORT_FILE_FULL))
            {
                DEBUG_WRAP(DebugMessage(DEBUG_FTPTELNET,
                  "FTP-DATA Processing Raw Packet\n"););

                finalFilePosition(&data_ssn->position);
                FTPDataProcess(p, data_ssn);
            }
        }

        return 0;
    }

    if (data_ssn->file_xfer_info == FTPP_FILE_UNKNOWN)
    {
        /* FTP-Data session is in limbo, we need to lookup the control session
         * to figure out what to do. */

        FtpFlowData* fd = (FtpFlowData*)stream.get_application_data_from_key(
            &data_ssn->ftp_key, FtpFlowData::flow_id);

        FTP_SESSION *ftp_ssn = fd ? &fd->session : NULL;

        if (!PROTO_IS_FTP(ftp_ssn))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_FTPTELNET,
              "FTP-DATA Invalid FTP_SESSION retrieved durring lookup\n"););

            if (data_ssn->data_chan)
                stream.set_ignore_direction(p->flow, SSN_DIR_BOTH);

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
                    stream.set_ignore_direction(p->flow, SSN_DIR_BOTH);
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

    if (FTPDataEOFDirection(p, data_ssn))
        finalFilePosition(&data_ssn->position);
    else
        initFilePosition(&data_ssn->position,
          file_api->get_file_processed_size(p->flow));

    FTPDataProcess(p, data_ssn);
    return 0;
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class FtpData : public Inspector
{
public:
    FtpData() { };
    ~FtpData() { };

    void eval(Packet*);
};

class FtpDataModule : public Module
{
public:
    FtpDataModule() : Module(s_name, s_help) { };

    const char** get_pegs() const;
    PegCount* get_counts() const;
    ProfileStats* get_profile() const;

    bool set(const char*, Value&, SnortConfig*)
    { return false; };
};

const char** FtpDataModule::get_pegs() const
{ return simple_pegs; }

PegCount* FtpDataModule::get_counts() const
{ return (PegCount*)&fdstats; }

ProfileStats* FtpDataModule::get_profile() const
{ return &ftpdataPerfStats; }

void FtpData::eval(Packet* p)
{
    // precondition - what we registered for
    assert(p->is_tcp());

    if ( file_api->get_max_file_depth() < 0 )
        return;

    PROFILE_VARS;
    MODULE_PROFILE_START(ftpdataPerfStats);

    SnortFTPData(p);
    ++fdstats.total_packets;

    MODULE_PROFILE_END(ftpdataPerfStats);
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
        s_name,
        s_help,
        INSAPI_PLUGIN_V0,
        0,
        mod_ctor,
        mod_dtor
    },
    IT_SERVICE,  // FIXIT-M does this still need to be session??
    (uint16_t)PktType::TCP,
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

