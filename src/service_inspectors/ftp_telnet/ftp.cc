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
#include "telnet.h"

#include "stream/stream_api.h"
#include "file_api/file_api.h"
#include "parser.h"
#include "framework/inspector.h"
#include "framework/plug_data.h"
#include "framework/share.h"
#include "detection/detection_util.h"

int16_t ftp_app_id = SFTARGET_UNKNOWN_PROTOCOL;
int16_t ftp_data_app_id = SFTARGET_UNKNOWN_PROTOCOL;

static const char* client_key = "ftp_client";
static const char* server_key = "ftp_server";
static const char* data_key = "ftp_data";

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats ftpPerfStats;
static THREAD_LOCAL PreprocStats ftpdataPerfStats;

static PreprocStats* ftp_get_profile(const char* key)
{
    if ( !strcmp(key, server_key) )
        return &ftpPerfStats;

    if ( !strcmp(key, data_key) )
        return &ftpdataPerfStats;

    return nullptr;
}
#endif

static THREAD_LOCAL SimpleStats ftstats;
static SimpleStats gftstats;

static FTP_CLIENT_PROTO_CONF* bind_client = nullptr;
static FTP_SERVER_PROTO_CONF* bind_server = nullptr;

FTP_CLIENT_PROTO_CONF* get_default_ftp_client()
{ return bind_client; }

FTP_SERVER_PROTO_CONF* get_default_ftp_server()
{ return bind_server; }

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
    FTP_DATA_SESSION *data_ssn;

    if (!p->flow)
        return -1;

    data_ssn = (FTP_DATA_SESSION *)
        p->flow->get_application_data(FtpFlowData::flow_id);

    if (!PROTO_IS_FTP_DATA(data_ssn))
        return -2;

    /* Do this now before splitting the work for rebuilt and raw packets. */
    if ((p->packet_flags & PKT_PDU_TAIL) || (p->tcph->th_flags & TH_FIN))
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

static inline int InspectClientPacket (Packet* p)
{
    return PacketHasPAFPayload(p);
}

static int SnortFTP(
    FTP_SESSION *FTPsession, Packet *p, int iInspectMode)
{
    int iRet;
    PROFILE_VARS;

    if (!FTPsession ||
         FTPsession->server_conf == NULL ||
         FTPsession->client_conf == NULL)
    {
        return FTPP_INVALID_SESSION;
    }

    if (!FTPsession->server_conf->check_encrypted_data &&
        ((FTPsession->encr_state == AUTH_TLS_ENCRYPTED) ||
         (FTPsession->encr_state == AUTH_SSL_ENCRYPTED) ||
         (FTPsession->encr_state == AUTH_UNKNOWN_ENCRYPTED)) )
    {
        return FTPP_SUCCESS;
    }

    PREPROC_PROFILE_START(ftpPerfStats);

    if (iInspectMode == FTPP_SI_SERVER_MODE)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FTPTELNET,
            "Server packet: %.*s\n", p->dsize, p->data));

        // FIXTHIS breaks target-based non-standard ports
        //if ( !ScPafEnabled() )
            /* Force flush of client side of stream  */
        stream.response_flush_stream(p);
    }
    else
    {
        if ( !InspectClientPacket(p) )
        {
            DEBUG_WRAP(DebugMessage(DEBUG_FTPTELNET,
                "Client packet will be reassembled\n"));
            PREPROC_PROFILE_END(ftpPerfStats);
            return FTPP_SUCCESS;
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_FTPTELNET,
                "Client packet: rebuilt %s: %.*s\n",
                (p->packet_flags & PKT_REBUILT_STREAM) ? "yes" : "no",
                p->dsize, p->data));
        }
    }

    iRet = initialize_ftp(FTPsession, p, iInspectMode);
    if (iRet)
    {
        PREPROC_PROFILE_END(ftpPerfStats);
        return iRet;
    }

    iRet = check_ftp(FTPsession, p, iInspectMode);
    if (iRet == FTPP_SUCCESS)
    {
        /* Ideally, Detect(), called from do_detection, will look at
         * the cmd & param buffers, or the rsp & msg buffers.  Current
         * architecture does not support this...
         * So, we call do_detection() here.  Otherwise, we'd call it
         * from inside check_ftp -- each time we process a pipelined
         * FTP command.
         */
        do_detection(p);
    }

    PREPROC_PROFILE_END(ftpPerfStats);
#ifdef PERF_PROFILING
    ft_update_perf(ftpPerfStats);
#endif

    return iRet;
}

static int snort_ftp(Packet *p)
{
    FTPP_SI_INPUT SiInput;
    int iInspectMode = FTPP_SI_NO_MODE;
    FTP_TELNET_SESSION *ft_ssn = NULL;

    /*
     * Set up the FTPP_SI_INPUT pointer.  This is what the session_inspection()
     * routines use to determine client and server traffic.  Plus, this makes
     * the FTPTelnet library very independent from snort.
     */
    SetSiInput(&SiInput, p);

    if (p->flow)
    {
        ft_ssn = (FTP_TELNET_SESSION*)
            p->flow->get_application_data(FtpFlowData::flow_id);

        if (ft_ssn != NULL)
        {
            SiInput.pproto = ft_ssn->proto;

            if (ft_ssn->proto == FTPP_SI_PROTO_FTP)
            {
                if (SiInput.pdir != FTPP_SI_NO_MODE)
                {
                    iInspectMode = SiInput.pdir;
                }
                else
                {
                    if ( p->packet_flags & PKT_FROM_SERVER )
                    {
                        iInspectMode = FTPP_SI_SERVER_MODE;
                    }
                    else if ( p->packet_flags & PKT_FROM_CLIENT )
                    {
                        iInspectMode = FTPP_SI_CLIENT_MODE;
                    }
                    else
                    {
                        iInspectMode = FTPGetPacketDir(p);
                    }
                }
            }
            else
            {
                /* XXX - Not FTP or Telnet */
                p->flow->free_application_data(FtpFlowData::flow_id);
                return 0;
            }
        }
    }

    if (ft_ssn == NULL)
    {
        SiInput.pproto = FTPP_SI_PROTO_UNKNOWN;
        iInspectMode = FTPP_SI_NO_MODE;

        FTPsessionInspection(p, (FTP_SESSION**)&ft_ssn, &SiInput, &iInspectMode);

        if ( SiInput.pproto != FTPP_SI_PROTO_FTP )
            return FTPP_INVALID_PROTO;
    }

    if (ft_ssn != NULL)
    {
        switch (SiInput.pproto)
        {
            case FTPP_SI_PROTO_FTP:
                return SnortFTP((FTP_SESSION *)ft_ssn, p, iInspectMode);
                break;
        }
    }

    /* Uh, shouldn't get here  */
    return FTPP_INVALID_PROTO;
}

/*
 * Function: ResetStringFormat (FTP_PARAM_FMT *Fmt)
 *
 * Purpose: Recursively sets nodes that allow strings to nodes that check
 *          for a string format attack within the FTP parameter validation tree
 *
 * Arguments: Fmt       => pointer to the FTP Parameter configuration
 *
 * Returns: None
 *
 */
static void ResetStringFormat (FTP_PARAM_FMT *Fmt)
{
    int i;
    if (!Fmt)
        return;

    if (Fmt->type == e_unrestricted)
        Fmt->type = e_strformat;

    ResetStringFormat(Fmt->optional_fmt);
    for (i=0;i<Fmt->numChoices;i++)
    {
        ResetStringFormat(Fmt->choices[i]);
    }
    ResetStringFormat(Fmt->next_param_fmt);
}

static int ProcessFTPDataChanCmdsList(
    FTP_SERVER_PROTO_CONF *ServerConf, const FtpCmd* fc)
{
    const char* cmd = fc->name.c_str();
    int iRet;

    FTP_CMD_CONF* FTPCmd = 
        ftp_cmd_lookup_find(ServerConf->cmd_lookup, cmd, strlen(cmd), &iRet);

        if (FTPCmd == NULL)
        {
            /* Add it to the list */
            // note that struct includes 1 byte for null, so just add len
            FTPCmd = (FTP_CMD_CONF *)calloc(1, sizeof(FTP_CMD_CONF)+strlen(cmd));
            if (FTPCmd == NULL)
            {
                ParseError("Failed to allocate memory");
            }

            strcpy(FTPCmd->cmd_name, cmd);

            // FIXIT make sure pulled from server conf when used if not
            // overridden
            //FTPCmd->max_param_len = ServerConf->def_max_param_len;

            ftp_cmd_lookup_add(ServerConf->cmd_lookup, cmd,
                               strlen(cmd), FTPCmd);
        }
        if ( fc->flags & CMD_DIR )
            FTPCmd->dir_response = fc->number;

        if ( fc->flags & CMD_LEN )
        {
            FTPCmd->max_param_len = fc->number;
            FTPCmd->max_param_len_overridden = 1;
        }
        if ( fc->flags & CMD_DATA )
            FTPCmd->data_chan_cmd = 1;

        if ( fc->flags & CMD_XFER )
            FTPCmd->data_xfer_cmd = 1;

        if ( fc->flags & CMD_PUT )
            FTPCmd->file_put_cmd = 1;

        if ( fc->flags & CMD_GET )
            FTPCmd->data_xfer_cmd = 1;

        if ( fc->flags & CMD_CHECK )
        {
            FTP_PARAM_FMT *Fmt = FTPCmd->param_format;
            if (Fmt)
            {
                ResetStringFormat(Fmt);
            }
            else
            {
                Fmt = (FTP_PARAM_FMT *)calloc(1, sizeof(FTP_PARAM_FMT));
                if (Fmt == NULL)
                {
                    ParseError("Failed to allocate memory");
                }

                Fmt->type = e_head;
                FTPCmd->param_format = Fmt;

                Fmt = (FTP_PARAM_FMT *)calloc(1, sizeof(FTP_PARAM_FMT));
                if (Fmt == NULL)
                {
                    ParseError("Failed to allocate memory");
                }

                Fmt->type = e_strformat;
                FTPCmd->param_format->next_param_fmt = Fmt;
                Fmt->prev_param_fmt = FTPCmd->param_format;
            }
            FTPCmd->check_validity = 1;
        }
        if ( fc->flags & CMD_VALID )
        {
            char err[1024];
            ProcessFTPCmdValidity(
                ServerConf, cmd, fc->format.c_str(), err, sizeof(err));
        }
        if ( fc->flags & CMD_ENCR )
            FTPCmd->encr_cmd = 1;

        if ( fc->flags & CMD_LOGIN )
            FTPCmd->login_cmd = 1;

    return 0;
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

typedef PlugDataType<FTP_CLIENT_PROTO_CONF> ClientData;

class FtpServer : public Inspector {
public:
    FtpServer(FTP_SERVER_PROTO_CONF*);
    ~FtpServer();

    bool configure(SnortConfig*);
    void show(SnortConfig*);
    void eval(Packet*);
    void eval_alt(Packet*);
    StreamSplitter* get_splitter(bool);

private:
    FTP_SERVER_PROTO_CONF* ftp_server;
    ClientData* ftp_client;  // FIXIT delete this when bindings implemented
};

FtpServer::FtpServer(FTP_SERVER_PROTO_CONF* server)
{
    ftp_server = server;
    ftp_client = nullptr;
}

FtpServer::~FtpServer ()
{
    CleanupFTPServerConf(ftp_server);
    free(ftp_server);

    if ( ftp_client )
        // FIXIT make sure CleanupFTPClientConf() is called
        Share::release(ftp_client);
}

bool FtpServer::configure (SnortConfig* sc)
{
    ftp_client = (ClientData*)Share::acquire(client_key);

    bind_server = ftp_server;
    bind_client = ftp_client->data;

    return !FTPCheckConfigs(sc, ftp_server);
}

void FtpServer::show(SnortConfig*)
{
    PrintFTPClientConf(ftp_client->data);
    PrintFTPServerConf(ftp_server);
}

StreamSplitter* FtpServer::get_splitter(bool c2s)
{
    return new FtpSplitter(c2s);
}

void FtpServer::eval_alt(Packet* p)
{
    // precondition - what we registered for
    assert(IsTCP(p) && p->data && p->dsize);

    ++ftstats.total_packets;
    snort_ftp(p);
}

void FtpServer::eval(Packet* p)
{
    // precondition - what we registered for
    assert(IsTCP(p));

    if ( file_api->get_max_file_depth() >= 0 )
    {
        if ( stream.get_application_protocol_id(p->flow)
            == ftp_data_app_id )
        {
            PROFILE_VARS;
            PREPROC_PROFILE_START(ftpdataPerfStats);
            ++ftstats.total_packets;
            SnortFTPData(p);
            PREPROC_PROFILE_END(ftpdataPerfStats);
            return;
        }
    }
    if ( !p->dsize || (p->data == NULL) )
        return;

    ++ftstats.total_packets;
    snort_ftp(p);
}

//-------------------------------------------------------------------------
// api stuff
//
// fc_ = ftp_client
// fs_ = ftp_server
//
// FIXIT fc is a data module but may need to
// be an inspector with separate bindings.
//-------------------------------------------------------------------------

static Module* fc_mod_ctor()
{ return new FtpClientModule; }

// this can be used for both modules
static void mod_dtor(Module* m)
{ delete m; }

static PlugData* fc_ctor(Module* m)
{
    FtpClientModule* mod = (FtpClientModule*)m;
    FTP_CLIENT_PROTO_CONF* gc = mod->get_data();
    unsigned i = 0;

    while ( const BounceTo* bt = mod->get_bounce(i++) )
    {
        printf("%s\n", bt->address.c_str());
        ProcessFTPAllowBounce(
            gc, (uint8_t*)bt->address.c_str(), bt->address.size(), bt->low, bt->high);
    }
    return new ClientData(gc);
}

static void fc_dtor(PlugData* p)
{ delete p; }

static const DataApi fc_api =
{
    {
        PT_DATA,
        client_key,
        MODAPI_PLUGIN_V0,
        0,
        fc_mod_ctor,
        mod_dtor
    },
    fc_ctor,
    fc_dtor
};

//-------------------------------------------------------------------------

static Module* fs_mod_ctor()
{ return new FtpServerModule; }

static void fs_init()
{
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile(
        server_key, &ftpPerfStats, 0, &totalPerfStats, ftp_get_profile);
    RegisterPreprocessorProfile(
        data_key, &ftpdataPerfStats, 0, &totalPerfStats, ftp_get_profile);
#endif

    ftp_app_id = AddProtocolReference("ftp");
    ftp_data_app_id = AddProtocolReference("ftp-data");

    FtpFlowData::init();
    FtpDataFlowData::init();
}

static Inspector* fs_ctor(Module* mod)
{
    FtpServerModule* fsm = (FtpServerModule*)mod;
    FTP_SERVER_PROTO_CONF* conf = fsm->get_data();
    unsigned i = 0;

    while ( const FtpCmd* cmd = fsm->get_cmd(i++) )
        ProcessFTPDataChanCmdsList(conf, cmd);

    return new FtpServer(conf);
}

static void fs_dtor(Inspector* p)
{
    delete p;
}

static void fs_sum()
{
    sum_stats(&gftstats, &ftstats);
}

static void fs_stats()
{
    show_stats(&gftstats, server_key);
}

static void fs_reset()
{
    memset(&gftstats, 0, sizeof(gftstats));
}

static const InspectApi fs_api =
{
    {
        PT_INSPECTOR,
        server_key,
        INSAPI_PLUGIN_V0,
        0,
        fs_mod_ctor,
        mod_dtor
    },
    //IT_SESSION,  // FIXIT should be service only
    IT_SERVICE,
    PROTO_BIT__TCP,
    nullptr, // buffers
    "ftp",   // FIXIT add ftp-data inspector
    fs_init,
    nullptr, // term
    fs_ctor,
    fs_dtor,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // ssn
    fs_sum,
    fs_stats,
    fs_reset
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &tn_api.base,
    &fc_api.base,
    &fs_api.base,
    nullptr
};
#else
const BaseApi* sin_telnet = &tn_api.base;
const BaseApi* sin_ftp_client = &fc_api.base;
const BaseApi* sin_ftp_server = &fs_api.base;
#endif

