//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

#include "telnet.h"

#include "detection/detection_engine.h"
#include "log/messages.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

#include "ft_main.h"
#include "ftp_print.h"
#include "telnet_splitter.h"
#include "ftpp_return_codes.h"
#include "ftpp_si.h"
#include "ftpp_ui_config.h"
#include "pp_telnet.h"
#include "telnet_module.h"

using namespace snort;

THREAD_LOCAL ProfileStats telnetPerfStats;
THREAD_LOCAL TelnetStats tnstats;

//-------------------------------------------------------------------------
// implementation
//-------------------------------------------------------------------------

static int TelnetCheckConfigs(SnortConfig*, void* pData)
{
    TELNET_PROTO_CONF* telnet_config = (TELNET_PROTO_CONF*)pData;

    if ((telnet_config->ayt_threshold > 0) &&
        !telnet_config->normalize)
    {
        ParseWarning(WARN_CONF, "telnet configuration check: using an "
            "AreYouThere threshold requires telnet normalization to be "
            "turned on.\n");
    }
    if ( telnet_config->detect_encrypted &&
        !telnet_config->normalize)
    {
        ParseWarning(WARN_CONF, "telnet configuration check: checking for "
            "encrypted traffic requires telnet normalization to be turned on.\n");
    }

    return 0;
}

static int SnortTelnet(TELNET_PROTO_CONF* telnet_config, TELNET_SESSION* Telnetsession,
    Packet* p, int iInspectMode)
{
    // cppcheck-suppress unreadVariable
    Profile profile(telnetPerfStats);

    if ( !Telnetsession )
        return FTPP_NONFATAL_ERR;

    if ( Telnetsession->encr_state &&
         !Telnetsession->telnet_conf->check_encrypted_data )
        return FTPP_SUCCESS;

    if ( telnet_config->normalize )
    {
        DataBuffer& buf = DetectionEngine::get_alt_buffer(p);
        int ret = normalize_telnet(Telnetsession, p, buf, iInspectMode,
            FTPP_APPLY_TNC_ERASE_CMDS, false);

        if ( ret == FTPP_SUCCESS || ret == FTPP_NORMALIZED )
            do_detection(p);
    }

    else
    {
        do_detection(p);
    }

    return FTPP_SUCCESS;
}

static int snort_telnet(TELNET_PROTO_CONF* GlobalConf, Packet* p)
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
        TelnetFlowData* fd = (TelnetFlowData*)
            p->flow->get_flow_data(FtpFlowData::inspector_id);

        ft_ssn = fd ? &fd->session.ft_ssn : nullptr;

        if (ft_ssn != nullptr)
        {
            SiInput.pproto = ft_ssn->proto;

            if (ft_ssn->proto == FTPP_SI_PROTO_TELNET)
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
                }
            }
            else
            {
                assert(false);
                p->flow->free_flow_data(FtpFlowData::inspector_id);
                return 0;
            }
        }
    }

    if (GlobalConf == nullptr)
        return 0;

    if (ft_ssn == nullptr)
    {
        SiInput.pproto = FTPP_SI_PROTO_UNKNOWN;
        iInspectMode = FTPP_SI_NO_MODE;

        TelnetsessionInspection(p, GlobalConf, (TELNET_SESSION**)&ft_ssn, &SiInput, &iInspectMode);

        if ( SiInput.pproto != FTPP_SI_PROTO_TELNET )
            return FTPP_INVALID_PROTO;
    }

    if (ft_ssn != nullptr)
    {
        switch (SiInput.pproto)
        {
        case FTPP_SI_PROTO_TELNET:
            return SnortTelnet(GlobalConf, (TELNET_SESSION*)ft_ssn, p, iInspectMode);
        }
    }

    /* Uh, shouldn't get here  */
    return FTPP_INVALID_PROTO;
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Telnet : public Inspector
{
public:
    Telnet(TELNET_PROTO_CONF*);
    ~Telnet() override;

    bool configure(SnortConfig*) override;
    void show(const SnortConfig*) const override;

    void eval(Packet*) override;
    void clear(Packet*) override;

    StreamSplitter* get_splitter(bool c2s) override
    { return new TelnetSplitter(c2s); }

private:
    TELNET_PROTO_CONF* config;
};

Telnet::Telnet(TELNET_PROTO_CONF* pc)
{
    config = pc;
}

Telnet::~Telnet()
{
    if ( config )
        delete config;
}

bool Telnet::configure(SnortConfig* sc)
{
    return !TelnetCheckConfigs(sc, config);
}

void Telnet::show(const SnortConfig*) const
{
    if ( !config )
        return;

    ConfigLogger::log_value("ayt_attack_thresh", config->ayt_threshold);
    ConfigLogger::log_flag("check_encrypted", config->detect_encrypted);
    ConfigLogger::log_flag("encrypted_traffic", config->check_encrypted_data);
    ConfigLogger::log_flag("normalize", config->normalize);
}

void Telnet::eval(Packet* p)
{
    // precondition - what we registered for
    assert(p->has_tcp_data());

    ++tnstats.total_packets;
    snort_telnet(config, p);
}

void Telnet::clear(Packet* p)
{
    reset_telnet_buffer(p);
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new TelnetModule; }

static void mod_dtor(Module* m)
{ delete m; }

static void tn_init()
{
    TelnetFlowData::init();
}

static Inspector* tn_ctor(Module* m)
{
    TelnetModule* mod = (TelnetModule*)m;
    return new Telnet(mod->get_data());
}

static void tn_dtor(Inspector* p)
{
    delete p;
}

// exported in ftp.cc
const InspectApi tn_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        TEL_NAME,
        TEL_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_SERVICE,
    PROTO_BIT__PDU,
    nullptr, // buffers
    "telnet",
    tn_init,
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    tn_ctor,
    tn_dtor,
    nullptr, // ssn
    nullptr  // reset
};

