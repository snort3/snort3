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

#include "telnet.h"
#include "pp_telnet.h"
#include "ftpp_si.h"
#include "ftpp_ui_config.h"
#include "ftpp_return_codes.h"
#include "ft_main.h"
#include "ftp_print.h"
#include "telnet_module.h"
#include "profiler.h"
#include "stream5/stream_api.h"
#include "file_api/file_api.h"
#include "parser.h"
#include "framework/inspector.h"
#include "utils/sfsnprintfappend.h"

int16_t telnet_app_id = SFTARGET_UNKNOWN_PROTOCOL;

static const char* tn_name = "telnet";

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats telnetPerfStats;

static PreprocStats* tn_get_profile(const char* key)
{
    if ( !strcmp(key, tn_name) )
        return &telnetPerfStats;

    return nullptr;
}
#endif

static THREAD_LOCAL SimpleStats tnstats;
static SimpleStats gtnstats;

//-------------------------------------------------------------------------
// implementation
//-------------------------------------------------------------------------

static int TelnetCheckConfigs(SnortConfig* sc, void* pData)
{
    TELNET_PROTO_CONF* telnet_config = (TELNET_PROTO_CONF*)pData;

    if ((telnet_config->ayt_threshold > 0) &&
            !telnet_config->normalize)
    {
         ErrorMessage("WARNING: Telnet Configuration Check: using an "
                 "AreYouThere threshold requires telnet normalization to be "
                 "turned on.\n");
    }
    if ( telnet_config->detect_encrypted &&
            !telnet_config->normalize)
    {
        ErrorMessage("WARNING: Telnet Configuration Check: checking for "
                "encrypted traffic requires telnet normalization to be turned "
                "on.\n");
    }

    _addPortsToStream5(sc, telnet_config->ports, 0);

    return 0;
}

static int SnortTelnet(TELNET_PROTO_CONF* telnet_config, TELNET_SESSION *Telnetsession,
                Packet *p, int iInspectMode)
{
    int iRet;
    PROFILE_VARS;

    if (!Telnetsession)
    {
        return FTPP_NONFATAL_ERR;
    }

    if (Telnetsession->encr_state && !Telnetsession->telnet_conf->check_encrypted_data)
    {
        return FTPP_SUCCESS;
    }

    PREPROC_PROFILE_START(telnetPerfStats);

    if (!telnet_config->normalize)
    {
        do_detection(p);
    }
    else
    {
        iRet = normalize_telnet(
            Telnetsession, p, iInspectMode, FTPP_APPLY_TNC_ERASE_CMDS);

        if ((iRet == FTPP_SUCCESS) || (iRet == FTPP_NORMALIZED))
        {
            do_detection(p);
        }
    }
    PREPROC_PROFILE_END(telnetPerfStats);
#ifdef PERF_PROFILING
    ft_update_perf(telnetPerfStats);
#endif

    return FTPP_SUCCESS;
}

static int snort_telnet(TELNET_PROTO_CONF* GlobalConf, Packet *p)
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
        ft_ssn = (FTP_TELNET_SESSION *)
            p->flow->get_application_data(FtpFlowData::flow_id);

        if (ft_ssn != NULL)
        {
            SiInput.pproto = ft_ssn->proto;

            if (ft_ssn->proto == FTPP_SI_PROTO_TELNET)
            {
                TELNET_SESSION *telnet_ssn = (TELNET_SESSION *)ft_ssn;

                if (SiInput.pdir != FTPP_SI_NO_MODE)
                {
                    iInspectMode = SiInput.pdir;
                }
                else
                {
                    if ((telnet_ssn->telnet_conf != NULL) &&
                        (telnet_ssn->telnet_conf->ports[SiInput.sport]))
                    {
                        iInspectMode = FTPP_SI_SERVER_MODE;
                    }
                    else if ((telnet_ssn->telnet_conf != NULL) &&
                             (telnet_ssn->telnet_conf->ports[SiInput.dport]))
                    {
                        iInspectMode = FTPP_SI_CLIENT_MODE;
                    }
                }
            }
            else
            {
                p->flow->free_application_data(FtpFlowData::flow_id);
                return 0;
            }
        }
    }

    if (GlobalConf == NULL)
        return 0;

    if (ft_ssn == NULL)
    {
        SiInput.pproto = FTPP_SI_PROTO_UNKNOWN;
        iInspectMode = FTPP_SI_NO_MODE;

        TelnetsessionInspection(p, GlobalConf, (TELNET_SESSION**)&ft_ssn, &SiInput, &iInspectMode);

        if ( SiInput.pproto != FTPP_SI_PROTO_TELNET )
            return FTPP_INVALID_PROTO;
    }

    if (ft_ssn != NULL)
    {
        switch (SiInput.pproto)
        {
            case FTPP_SI_PROTO_TELNET:
                return SnortTelnet(GlobalConf, (TELNET_SESSION *)ft_ssn, p, iInspectMode);
                break;
        }
    }

    /* Uh, shouldn't get here  */
    return FTPP_INVALID_PROTO;
}

/*
 * Function: PrintTelnetConf(TELNET_PROTO_CONF *TelnetConf,
 *                          char *Option)
 *
 * Purpose: Prints the telnet configuration
 *
 * Arguments: TelnetConf    => pointer to the telnet configuration
 *
 * Returns: int     => an error code integer (0 = success,
 *                     >0 = non-fatal error, <0 = fatal error)
 *
 */
static int PrintTelnetConf(TELNET_PROTO_CONF *TelnetConf)
{
    char buf[BUF_SIZE+1];
    int iCtr;

    if(!TelnetConf)
    {
        return FTPP_INVALID_ARG;
    }

    LogMessage("    TELNET CONFIG:\n");
    memset(buf, 0, BUF_SIZE+1);
    snprintf(buf, BUF_SIZE, "      Ports: ");

    /*
     * Print out all the applicable ports.
     */
    for(iCtr = 0; iCtr < MAXPORTS; iCtr++)
    {
        if(TelnetConf->ports[iCtr])
        {
            sfsnprintfappend(buf, BUF_SIZE, "%d ", iCtr);
        }
    }

    LogMessage("%s\n", buf);
    LogMessage("      Are You There Threshold: %d\n",
        TelnetConf->ayt_threshold);
    LogMessage("      Normalize: %s\n", TelnetConf->normalize ? "YES" : "NO");
    LogMessage("      Detect Anomalies: %s\n",
            TelnetConf->detect_anomalies ? "YES" : "NO");
    PrintConfOpt(TelnetConf->detect_encrypted, "Check for Encrypted Traffic");
    LogMessage("      Continue to check encrypted data: %s\n",
        TelnetConf->check_encrypted_data ? "YES" : "NO");

    return FTPP_SUCCESS;
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Telnet : public Inspector {
public:
    Telnet(TELNET_PROTO_CONF*);
    ~Telnet();

    void configure(SnortConfig*);
    int verify(SnortConfig*);
    void show(SnortConfig*);
    void eval(Packet*);

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

void Telnet::configure(SnortConfig* sc)
{
    stream.set_service_filter_status(
        sc, telnet_app_id, PORT_MONITOR_SESSION);
}

int Telnet::verify(SnortConfig* sc)
{
    return TelnetCheckConfigs(sc, config);
}

void Telnet::show(SnortConfig*)
{
    PrintTelnetConf(config);
}

void Telnet::eval(Packet* p)
{
    // precondition - what we registered for
    assert(IsTCP(p) && p->dsize && p->data);

    ++tnstats.total_packets;
    snort_telnet(config, p);
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static void tn_init()
{
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile(
        tn_name, &telnetPerfStats, 0, &totalPerfStats, tn_get_profile);
#endif

    telnet_app_id = AddProtocolReference(tn_name);
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

static void tn_sum(void*)
{
    sum_stats(&gtnstats, &tnstats);
}

static void tn_stats(void*)
{
    show_stats(&gtnstats, tn_name);
}

static void tn_reset(void*)
{
    memset(&gtnstats, 0, sizeof(gtnstats));
}

// exported in ftp.cc
const InspectApi tn_api =
{
    {
        PT_INSPECTOR,
        tn_name,
        INSAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr
    },
    PRIORITY_APPLICATION,
    PROTO_BIT__TCP,
    tn_init,
    nullptr, // term
    tn_ctor,
    tn_dtor,
    nullptr, // stop
    nullptr, // purge
    tn_sum,
    tn_stats,
    tn_reset
};

