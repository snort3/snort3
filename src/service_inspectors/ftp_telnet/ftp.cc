//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#include "main/snort_config.h"
#include "managers/inspector_manager.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "stream/stream.h"
#include "target_based/snort_protocols.h"
#include "utils/util.h"

#include "ft_main.h"
#include "ftp_cmd_lookup.h"
#include "ftp_data.h"
#include "ftp_module.h"
#include "ftp_parse.h"
#include "ftp_print.h"
#include "ftp_splitter.h"
#include "ftpp_return_codes.h"
#include "ftpp_si.h"
#include "pp_ftp.h"
#include "telnet.h"

using namespace snort;

SnortProtocolId ftp_data_snort_protocol_id = UNKNOWN_PROTOCOL_ID;

#define client_help "FTP inspector client module"
#define server_help "FTP inspector server module"

THREAD_LOCAL ProfileStats ftpPerfStats;
THREAD_LOCAL FtpStats ftstats;

//-------------------------------------------------------------------------
// implementation stuff
//-------------------------------------------------------------------------

static inline int InspectClientPacket(Packet* p)
{
    return p->has_paf_payload();
}

static int SnortFTP(
    FTP_SESSION* FTPsession, Packet* p, int iInspectMode)
{
    Profile profile(ftpPerfStats);

    if ( !FTPsession || !FTPsession->server_conf || !FTPsession->client_conf )
        return FTPP_INVALID_SESSION;

    if ( !FTPsession->server_conf->check_encrypted_data )
    {
        if ( FTPsession->encr_state == AUTH_TLS_ENCRYPTED ||
             FTPsession->encr_state == AUTH_SSL_ENCRYPTED ||
             FTPsession->encr_state == AUTH_UNKNOWN_ENCRYPTED )

            return FTPP_SUCCESS;
    }

    if (iInspectMode == FTPP_SI_SERVER_MODE)
    {
        // FIXIT-L breaks target-based non-standard ports
        //if ( !ScPafEnabled() )
        Stream::flush_client(p);
    }
    else if ( !InspectClientPacket(p) )
        return FTPP_SUCCESS;

    int ret = initialize_ftp(FTPsession, p, iInspectMode);
    if ( ret )
        return ret;

    ret = check_ftp(FTPsession, p, iInspectMode);
    if ( ret == FTPP_SUCCESS )
    {
        NoProfile exclude(ftpPerfStats);

        // FIXIT-L ideally do_detection will look at the cmd & param buffers
        // or the rsp & msg buffers.  We should call it from inside check_ftp
        // each time we process a pipelined FTP command.

        do_detection(p);
    }

    return ret;
}

static int snort_ftp(Packet* p)
{
    FTPP_SI_INPUT SiInput;
    int iInspectMode = FTPP_SI_NO_MODE;
    FTP_TELNET_SESSION* ft_ssn = nullptr;

    /*
     * Set up the FTPP_SI_INPUT pointer.  This is what the session_inspection()
     * routines use to determine client and server traffic.  Plus, this makes
     * the FTPTelnet library very independent from snort.
     */
    SetSiInput(&SiInput, p);

    if (p->flow)
    {
        FtpFlowData* fd = (FtpFlowData*)p->flow->get_flow_data(FtpFlowData::inspector_id);
        ft_ssn = fd ? &fd->session.ft_ssn : nullptr;

        if (ft_ssn != nullptr)
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
                    if ( p->is_from_server() )
                    {
                        iInspectMode = FTPP_SI_SERVER_MODE;
                    }
                    else if ( p->is_from_client() )
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
                assert(false);
                p->flow->free_flow_data(FtpFlowData::inspector_id);
                return 0;
            }
        }
    }

    if (ft_ssn == nullptr)
    {
        SiInput.pproto = FTPP_SI_PROTO_UNKNOWN;
        iInspectMode = FTPP_SI_NO_MODE;

        FTPsessionInspection(p, (FTP_SESSION**)&ft_ssn, &SiInput, &iInspectMode);

        if ( SiInput.pproto != FTPP_SI_PROTO_FTP )
            return FTPP_INVALID_PROTO;
    }

    if (ft_ssn != nullptr)
    {
        switch (SiInput.pproto)
        {
        case FTPP_SI_PROTO_FTP:
            return SnortFTP((FTP_SESSION*)ft_ssn, p, iInspectMode);
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
static void ResetStringFormat(FTP_PARAM_FMT* Fmt)
{
    int i;
    if (!Fmt)
        return;

    if (Fmt->type == e_unrestricted)
        Fmt->type = e_strformat;

    ResetStringFormat(Fmt->optional_fmt);
    for (i=0; i<Fmt->numChoices; i++)
    {
        ResetStringFormat(Fmt->choices[i]);
    }
    ResetStringFormat(Fmt->next_param_fmt);
}

static int ProcessFTPDataChanCmdsList(
    FTP_SERVER_PROTO_CONF* ServerConf, const FtpCmd* fc)
{
    const char* cmd = fc->name.c_str();
    int iRet;

    FTP_CMD_CONF* FTPCmd =
        ftp_cmd_lookup_find(ServerConf->cmd_lookup, cmd, strlen(cmd), &iRet);

    if (FTPCmd == nullptr)
    {
        /* Add it to the list */
        // note that struct includes 1 byte for null, so just add len
        FTPCmd = (FTP_CMD_CONF*)snort_calloc(sizeof(FTP_CMD_CONF)+strlen(cmd));
        strncpy(FTPCmd->cmd_name, cmd, strlen(cmd) + 1);

        // FIXIT-L make sure pulled from server conf when used if not overridden
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
        FTPCmd->data_chan_cmd = true;

    if ( fc->flags & CMD_REST )
        FTPCmd->data_rest_cmd = true;

    if ( fc->flags & CMD_XFER )
        FTPCmd->data_xfer_cmd = true;

    if ( fc->flags & CMD_PUT )
        FTPCmd->file_put_cmd = true;

    if ( fc->flags & CMD_GET )
        FTPCmd->file_get_cmd = true;

    if ( fc->flags & CMD_CHECK )
    {
        FTP_PARAM_FMT* Fmt = FTPCmd->param_format;
        if (Fmt)
        {
            ResetStringFormat(Fmt);
        }
        else
        {
            Fmt = (FTP_PARAM_FMT*)snort_calloc(sizeof(FTP_PARAM_FMT));
            Fmt->type = e_head;
            FTPCmd->param_format = Fmt;

            Fmt = (FTP_PARAM_FMT*)snort_calloc(sizeof(FTP_PARAM_FMT));
            Fmt->type = e_strformat;
            FTPCmd->param_format->next_param_fmt = Fmt;
            Fmt->prev_param_fmt = FTPCmd->param_format;
        }
        FTPCmd->check_validity = true;
    }
    if ( fc->flags & CMD_VALID )
    {
        char err[1024];
        ProcessFTPCmdValidity(
            ServerConf, cmd, fc->format.c_str(), err, sizeof(err));
    }
    if ( fc->flags & CMD_ENCR )
        FTPCmd->encr_cmd = true;

    if ( fc->flags & CMD_LOGIN )
        FTPCmd->login_cmd = true;

    return 0;
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

typedef InspectorData<FTP_CLIENT_PROTO_CONF> FtpClient;

class FtpServer : public Inspector
{
public:
    FtpServer(FTP_SERVER_PROTO_CONF*);
    ~FtpServer() override;

    bool configure(SnortConfig*) override;
    void show(SnortConfig*) override;
    void eval(Packet*) override;
    StreamSplitter* get_splitter(bool) override;

    FTP_SERVER_PROTO_CONF* ftp_server;
};

FtpServer::FtpServer(FTP_SERVER_PROTO_CONF* server)
{
    ftp_server = server;
}

FtpServer::~FtpServer ()
{
    CleanupFTPServerConf(ftp_server);
    delete ftp_server;
}

bool FtpServer::configure(SnortConfig* sc)
{
    ftp_data_snort_protocol_id = sc->proto_ref->add("ftp-data");
    return !FTPCheckConfigs(sc, ftp_server);
}

void FtpServer::show(SnortConfig*)
{
    PrintFTPServerConf(ftp_server);
}

StreamSplitter* FtpServer::get_splitter(bool c2s)
{
    return new FtpSplitter(c2s);
}

void FtpServer::eval(Packet* p)
{
    // precondition - what we registered for
    assert(p->has_tcp_data());

    ++ftstats.total_packets;
    snort_ftp(p);
}

//-------------------------------------------------------------------------
// get the relevant configs required by legacy ftp code
// the client must be found if not explicitly bound

FTP_CLIENT_PROTO_CONF* get_ftp_client(Packet* p)
{
    FtpClient* client = (FtpClient*)p->flow->data;
    if ( !client )
    {
        client = (FtpClient*)InspectorManager::get_inspector(FTP_CLIENT_NAME);
        assert(client);
        p->flow->set_data(client);
    }
    return client->data;
}

FTP_SERVER_PROTO_CONF* get_ftp_server(Packet* p)
{
    FtpServer* server = (FtpServer*)p->flow->gadget;
    assert(server);
    return server->ftp_server;
}

//-------------------------------------------------------------------------
// api stuff
//
// fc_ = ftp_client
// fs_ = ftp_server
//-------------------------------------------------------------------------

static Module* fc_mod_ctor()
{ return new FtpClientModule; }

// this can be used for both modules
static void mod_dtor(Module* m)
{ delete m; }

static Inspector* fc_ctor(Module* m)
{
    FtpClientModule* mod = (FtpClientModule*)m;
    FTP_CLIENT_PROTO_CONF* gc = mod->get_data();
    unsigned i = 0;

    while ( const BounceTo* bt = mod->get_bounce(i++) )
    {
        ProcessFTPAllowBounce(
            gc, (const uint8_t*)bt->address.c_str(), bt->address.size(), bt->low, bt->high);
    }
    return new FtpClient(gc);
}

static void fc_dtor(Inspector* p)
{ delete p; }

static const InspectApi fc_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        FTP_CLIENT_NAME,
        client_help,
        fc_mod_ctor,
        mod_dtor
    },
    IT_PASSIVE,
    PROTO_BIT__NONE,
    nullptr, // buffers
    "ftp",
    nullptr, // init,
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    fc_ctor,
    fc_dtor,
    nullptr, // ssn
    nullptr  // reset
};

//-------------------------------------------------------------------------

static Module* fs_mod_ctor()
{ return new FtpServerModule; }

static void fs_init()
{
    FtpFlowData::init();
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

static const InspectApi fs_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        FTP_SERVER_NAME,
        server_help,
        fs_mod_ctor,
        mod_dtor
    },
    IT_SERVICE,
    PROTO_BIT__PDU,
    nullptr, // buffers
    "ftp",
    fs_init,
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    fs_ctor,
    fs_dtor,
    nullptr, // ssn
    nullptr  // reset
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &fc_api.base,
    &fs_api.base,
    &fd_api.base,
    &tn_api.base,
    nullptr
};
#else
const BaseApi* sin_telnet = &tn_api.base;
const BaseApi* sin_ftp_client = &fc_api.base;
const BaseApi* sin_ftp_server = &fs_api.base;
const BaseApi* sin_ftp_data = &fd_api.base;
#endif

