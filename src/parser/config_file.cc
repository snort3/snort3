/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2013-2013 Sourcefire, Inc.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include "config_file.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <stdarg.h>
#include <pcap.h>
#include <grp.h>
#include <pwd.h>
#include <syslog.h>

#ifdef HAVE_DUMBNET_H
#include <dumbnet.h>
#else
#include <dnet.h>
#endif

#include "snort_types.h"
#include "snort_bounds.h"
#include "snort_debug.h"
#include "parser.h"
#include "cmd_line.h"
#include "mstring.h"
#include "util.h"
#include "utils/strvec.h"
#include "keywords.h"
#include "parser.h"
#include "ips_options/ips_flowbits.h"
#include "file_api/file_service_config.h"
#include "packet_io/sfdaq.h"
#include "target_based/sftarget_reader.h"
#include "managers/event_manager.h"
#include "detection/detect.h"

#define LOG_NONE  "none"
#define LOG_TEXT  "text"
#define LOG_PCAP  "pcap"

#define ALERT_NONE    "none"
#define ALERT_CMG     "cmg"
#define ALERT_JH      "jh"
#define ALERT_DJR     "djr"
#define ALERT_AJK     "ajk"

#define OUTPUT_AJK  "unified2"
#define OUTPUT_CMG  "alert_fast"
#define OUTPUT_PCAP "log_tcpdump"

static std::string lua_conf;
static std::string snort_conf_dir;

const char* get_snort_conf()
{ return lua_conf.c_str(); }

const char* get_snort_conf_dir()
{ return snort_conf_dir.c_str(); }

void ConfigAlertBeforePass(SnortConfig *sc, const char*)
{
    sc->run_flags |= RUN_FLAG__ALERT_BEFORE_PASS;
}

static int GetChecksumFlags(const char *args)
{
    char **toks;
    int num_toks;
    int i;
    int negative_flags = 0;
    int positive_flags = 0;
    int got_positive_flag = 0;
    int got_negative_flag = 0;
    int ret_flags = 0;

    if (args == NULL)
        return CHECKSUM_FLAG__ALL;

    toks = mSplit(args, " \t", 10, &num_toks, 0);
    for (i = 0; i < num_toks; i++)
    {
        if (strcasecmp(toks[i], CHECKSUM_MODE_OPT__ALL) == 0)
        {
            positive_flags = CHECKSUM_FLAG__ALL;
            negative_flags = 0;
            got_positive_flag = 1;
        }
        else if (strcasecmp(toks[i], CHECKSUM_MODE_OPT__NONE) == 0)
        {
            positive_flags = 0;
            negative_flags = CHECKSUM_FLAG__ALL;
            got_negative_flag = 1;
        }
        else if (strcasecmp(toks[i], CHECKSUM_MODE_OPT__IP) == 0)
        {
            positive_flags |= CHECKSUM_FLAG__IP;
            negative_flags &= ~CHECKSUM_FLAG__IP;
            got_positive_flag = 1;
        }
        else if (strcasecmp(toks[i], CHECKSUM_MODE_OPT__NO_IP) == 0)
        {
            positive_flags &= ~CHECKSUM_FLAG__IP;
            negative_flags |= CHECKSUM_FLAG__IP;
            got_negative_flag = 1;
        }
        else if (strcasecmp(toks[i], CHECKSUM_MODE_OPT__TCP) == 0)
        {
            positive_flags |= CHECKSUM_FLAG__TCP;
            negative_flags &= ~CHECKSUM_FLAG__TCP;
            got_positive_flag = 1;
        }
        else if (strcasecmp(toks[i], CHECKSUM_MODE_OPT__NO_TCP) == 0)
        {
            positive_flags &= ~CHECKSUM_FLAG__TCP;
            negative_flags |= CHECKSUM_FLAG__TCP;
            got_negative_flag = 1;
        }
        else if (strcasecmp(toks[i], CHECKSUM_MODE_OPT__UDP) == 0)
        {
            positive_flags |= CHECKSUM_FLAG__UDP;
            negative_flags &= ~CHECKSUM_FLAG__UDP;
            got_positive_flag = 1;
        }
        else if (strcasecmp(toks[i], CHECKSUM_MODE_OPT__NO_UDP) == 0)
        {
            positive_flags &= ~CHECKSUM_FLAG__UDP;
            negative_flags |= CHECKSUM_FLAG__UDP;
            got_negative_flag = 1;
        }
        else if (strcasecmp(toks[i], CHECKSUM_MODE_OPT__ICMP) == 0)
        {
            positive_flags |= CHECKSUM_FLAG__ICMP;
            negative_flags &= ~CHECKSUM_FLAG__ICMP;
            got_positive_flag = 1;
        }
        else if (strcasecmp(toks[i], CHECKSUM_MODE_OPT__NO_ICMP) == 0)
        {
            positive_flags &= ~CHECKSUM_FLAG__ICMP;
            negative_flags |= CHECKSUM_FLAG__ICMP;
            got_negative_flag = 1;
        }
        else
        {
            ParseError("unknown command line checksum option: %s.", toks[i]);
            return ret_flags;
        }
    }

    /* Invert the negative flags with all checksums */
    negative_flags ^= CHECKSUM_FLAG__ALL;
    negative_flags &= CHECKSUM_FLAG__ALL;

    if (got_positive_flag && got_negative_flag)
    {
        /* If we got both positive and negative flags just take the
         * combination of the two */
        ret_flags = positive_flags & negative_flags;
    }
    else if (got_positive_flag)
    {
        /* If we got a positive flag assume the user wants checksums
         * to be cleared */
        ret_flags = positive_flags;
    }
    else  /* got a negative flag */
    {
        /* If we got a negative flag assume the user thinks all
         * checksums are on */
        ret_flags = negative_flags;
    }

    mSplitFree(&toks, num_toks);
    return ret_flags;
}

void ConfigChecksumDrop(SnortConfig*, const char *args)
{
    NetworkPolicy* policy = get_network_policy();
    policy->checksum_drop = GetChecksumFlags(args);
}

void ConfigChecksumMode(SnortConfig*, const char *args)
{
    NetworkPolicy* policy = get_network_policy();
    policy->checksum_eval = GetChecksumFlags(args);
}

void ConfigChrootDir(SnortConfig *sc, const char *args)
{
    if ((args == NULL) || (sc->chroot_dir != NULL))
        return;

    sc->chroot_dir = SnortStrdup(args);
}

void ConfigCreatePidFile(SnortConfig *sc, const char*)
{
    sc->run_flags |= RUN_FLAG__CREATE_PID_FILE;
}

void ConfigDaemon(SnortConfig *sc, const char*)
{
    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Daemon mode flag set\n"););
    sc->run_flags |= RUN_FLAG__DAEMON;
    sc->logging_flags |= LOGGING_FLAG__QUIET;
}

void ConfigDecodeDataLink(SnortConfig *sc, const char*)
{
    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Decode DLL set\n"););
    sc->output_flags |= OUTPUT_FLAG__SHOW_DATA_LINK;
}

void ConfigDumpCharsOnly(SnortConfig* sc, const char*)
{
    /* dump the application layer as text only */
    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Character payload dump set\n"););
    sc->output_flags |= OUTPUT_FLAG__CHAR_DATA;
}

void ConfigDumpPayload(SnortConfig *sc, const char*)
{
    /* dump the application layer */
    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Payload dump set\n"););
    sc->output_flags |= OUTPUT_FLAG__APP_DATA;
}

void ConfigDumpPayloadVerbose(SnortConfig *sc, const char*)
{
    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Verbose packet bytecode dumps enabled\n"););
    sc->output_flags |= OUTPUT_FLAG__VERBOSE_DUMP;
}

#define GTP_U_PORT 2152
#define GTP_U_PORT_V0 3386
void ConfigGTPDecoding(SnortConfig *sc, const char*)
{
    PortObject *portObject;
    int numberOfPorts = 0;

    /*Set the ports*/
    portObject = PortVarTableFind(get_ips_policy()->portVarTable, "GTP_PORTS");

    if (portObject)
    {
       sc->gtp_ports =  PortObjectCharPortArray(sc->gtp_ports,portObject, &numberOfPorts);
    }

    if (!sc->gtp_ports || (0 == numberOfPorts))
    {
        /*No ports defined, use default GTP ports*/
        sc->gtp_ports = (char *)SnortAlloc(UINT16_MAX);
        sc->gtp_ports[GTP_U_PORT] = 1;
        sc->gtp_ports[GTP_U_PORT_V0] = 1;
    }
}

void ConfigDstMac(SnortConfig* sc, const char* s)
{
    eth_addr_t dst;

    if ( eth_pton(s, &dst) < 0 )
    {
        ParseError("format check failed: %s,  Use format like 12:34:56:78:90:1a", s);
        return;
    }
    sc->eth_dst = (uint8_t*)SnortAlloc (sizeof(dst.data));
    memcpy(sc->eth_dst, dst.data, sizeof(dst.data));
}

void ConfigLogDir(SnortConfig *sc, const char *args)
{
    if ((args == NULL) || (sc->log_dir != NULL))
        return;

    sc->log_dir = SnortStrdup(args);
}

void ConfigDaqType(SnortConfig *sc, const char *args)
{
    if ( !args || !sc )
        return;

    if ( sc->daq_type )
    {
        ParseError("setting DAQ to %s but %s already selected.", args, sc->daq_type);
        return;
    }

    // will be validated later after paths are established
    sc->daq_type = SnortStrdup(args);
}

void ConfigDaqMode(SnortConfig *sc, const char *args)
{
    if ( !args || !sc || sc->daq_mode )
        return;

    // will be validated later when daq is instantiated
    sc->daq_mode = SnortStrdup(args);
}

void ConfigDaqVar(SnortConfig *sc, const char *args)
{
    if ( !args || !sc )
        return;

    if ( !sc->daq_vars )
    {
        sc->daq_vars = StringVector_New();

        if ( !sc->daq_vars )
        {
            ParseError("can't allocate memory for daq_var '%s'.", args);
            return;
        }
    }
    if ( !StringVector_Add(sc->daq_vars, args) )
        ParseError("can't allocate memory for daq_var '%s'.", args);
}

void ConfigDaqDir(SnortConfig *sc, const char *args)
{
    if ( !args || !sc )
        return;

    if ( !sc->daq_dirs )
    {
        sc->daq_dirs = StringVector_New();

        if ( !sc->daq_dirs )
        {
            ParseError("can't allocate memory for daq_dir '%s'.", args);
            return;
        }
    }
    if ( !StringVector_Add(sc->daq_dirs, args) )
        ParseError("can't allocate memory for daq_dir '%s'.", args);
}

void ConfigDirtyPig(SnortConfig* sc, const char*)
{
    if ( sc )
        sc->dirty_pig = 1;
}

void ConfigNoLog(SnortConfig *sc, const char*)
{
    sc->output_flags |= OUTPUT_FLAG__NO_LOG;
}

void ConfigObfuscate(SnortConfig *sc, const char*)
{
    sc->output_flags |= OUTPUT_FLAG__OBFUSCATE;
}

void ConfigNoLoggingTimestamps(SnortConfig *sc, const char*)
{
    sc->output_flags |= OUTPUT_FLAG__NO_TIMESTAMP;
}

void ConfigObfuscationMask(SnortConfig *sc, const char *args)
{
    if ( !args )
        return;

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Got obfus data: %s\n", args););

    sc->output_flags |= OUTPUT_FLAG__OBFUSCATE;

    sfip_pton(args, &sc->obfuscation_net);
}

PolicyMode GetPolicyMode(PolicyMode mode)
{
    switch ( mode )
    {
    case POLICY_MODE__PASSIVE:
        if ( ScAdapterInlineTestMode() )
            mode = POLICY_MODE__INLINE_TEST;
        break;

    case POLICY_MODE__INLINE:
        /* If --enable-inline-test is specified it overwrites
         * policy_mode: inline */
        if( ScAdapterInlineTestMode() )
            mode = POLICY_MODE__INLINE_TEST;

        else if (!ScAdapterInlineMode())
        {
           ParseWarning("Adapter is in Passive Mode. Hence switching "
                   "policy mode to tap.");
           mode = POLICY_MODE__PASSIVE;
        }
        break;

    case POLICY_MODE__INLINE_TEST:
        break;

    default:
        ParseError("unknown command line policy mode option: %d.", mode);
    }
    return mode;
}

#ifdef PERF_PROFILING
void ConfigProfiling(SnortConfig* sc)
{   
    if ( sc->profile_rules.filename )
    {
        char* fn = ProcessFileOption(sc, sc->profile_rules.filename);
        free(sc->profile_rules.filename);
        sc->profile_rules.filename = fn;
    }
    if ( sc->profile_preprocs.filename )
    {
        char* fn = ProcessFileOption(sc, sc->profile_preprocs.filename);
        free(sc->profile_preprocs.filename);
        sc->profile_preprocs.filename = fn;
    }

}
#endif

void ConfigQuiet(SnortConfig *sc, const char*)
{
    sc->logging_flags |= LOGGING_FLAG__QUIET;
}

void ConfigSetGid(SnortConfig *sc, const char *args)
{
    size_t i;
    char *endptr;

    if ( !args )
        return;

    for (i = 0; i < strlen(args); i++)
    {
        /* If we get something other than a digit, assume it's
         * a group name */
        if (!isdigit((int)args[i]))
        {
            struct group *gr = getgrnam(args);  // main thread only

            if (gr == NULL)
            {
                ParseError("group '%s' unknown.", args);
                return;
            }

            sc->group_id = gr->gr_gid;
            break;
        }
    }

    /* It's all digits.  Assume it's a group id */
    if (i == strlen(args))
    {
        sc->group_id = SnortStrtol(args, &endptr, 10);
        if ((errno == ERANGE) || (*endptr != '\0') ||
            (sc->group_id < 0))
        {
            ParseError("group id '%s' out of range.", args);
        }
    }
}

void ConfigSetUid(SnortConfig *sc, const char *args)
{
    size_t i;
    char *endptr;

    if ( !args )
        return;

    for (i = 0; i < strlen(args); i++)
    {
        /* If we get something other than a digit, assume it's
         * a user name */
        if (!isdigit((int)args[i]))
        {
            struct passwd *pw = getpwnam(args);  // main thread only

            if (pw == NULL)
            {
                ParseError("user '%s' unknown.", args);
                return;
            }

            sc->user_id = (int)pw->pw_uid;

            /* Why would someone want to run as another user
             * but still as root group? */
            if (sc->group_id == -1)
                sc->group_id = (int)pw->pw_gid;

            break;
        }
    }

    /* It's all digits.  Assume it's a user id */
    if (i == strlen(args))
    {
        sc->user_id = SnortStrtol(args, &endptr, 10);
        if ((errno == ERANGE) || (*endptr != '\0'))
        {
            ParseError("user id '%s' out of range.", args);
            return;
        }

        /* Set group id to user's default group if not
         * already set */
        if (sc->group_id == -1)
        {
            struct passwd *pw = getpwuid((uid_t)sc->user_id);  // main thread only

            if (pw == NULL)
            {
                ParseError("user '%s' unknown.", args);
                return;
            }

            sc->group_id = (int)pw->pw_gid;
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "UserID: %d GroupID: %d.\n",
                            sc->user_id, sc->group_id););
}

void ConfigShowYear(SnortConfig *sc, const char*)
{
    sc->output_flags |= OUTPUT_FLAG__INCLUDE_YEAR;
    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Enabled year in timestamp\n"););
}

void ConfigTreatDropAsAlert(SnortConfig *sc, const char*)
{
    sc->run_flags |= RUN_FLAG__TREAT_DROP_AS_ALERT;
}

void ConfigTreatDropAsIgnore(SnortConfig *sc, const char*)
{
    sc->run_flags |= RUN_FLAG__TREAT_DROP_AS_IGNORE;
}

void ConfigProcessAllEvents(SnortConfig* sc, const char*)
{
    sc->run_flags |= RUN_FLAG__PROCESS_ALL_EVENTS;
}

#ifdef ACCESSPERMS
# define FILEACCESSBITS ACCESSPERMS
#else
# ifdef S_IAMB
#  define FILEACCESSBITS S_IAMB
# else
#  define FILEACCESSBITS 0x1FF
# endif
#endif

void ConfigUmask(SnortConfig *sc, const char *args)
{
    char *endptr;
    long mask;

    mask = SnortStrtol(args, &endptr, 0);

    if ((errno == ERANGE) || (*endptr != '\0') ||
        (mask < 0) || (mask & ~FILEACCESSBITS))
    {
        ParseError("bad umask: %s", args);
    }
    sc->file_mask = (mode_t)mask;
}

void ConfigUtc(SnortConfig *sc, const char*)
{
    sc->output_flags |= OUTPUT_FLAG__USE_UTC;
}

void ConfigVerbose(SnortConfig *sc, const char*)
{
    sc->logging_flags |= LOGGING_FLAG__VERBOSE;
    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Verbose Flag active\n"););
}

void ConfigTunnelVerdicts ( SnortConfig *sc, const char *args )
{
    char* tmp, *tok;

    tmp = SnortStrdup(args);
    char* lasts = { 0 };
    tok = strtok_r(tmp, " ,", &lasts);

    while ( tok )
    {
        if ( !strcasecmp(tok, "gtp") )
            sc->tunnel_mask |= TUNNEL_GTP;

        else if ( !strcasecmp(tok, "teredo") )
            sc->tunnel_mask |= TUNNEL_TEREDO;

        else if ( !strcasecmp(tok, "6in4") )
            sc->tunnel_mask |= TUNNEL_6IN4;

        else if ( !strcasecmp(tok, "4in6") )
            sc->tunnel_mask |= TUNNEL_4IN6;

        else
        {
            ParseError("unknown tunnel bypass protocol");
            return;
        }

        tok = strtok_r(NULL, " ,", &lasts);
    }
    free(tmp);
}

void ConfigPluginPath(SnortConfig *sc, const char *args)
{
    if ( sc && args )
        sc->plugin_path = SnortStrdup(args);
}

void ConfigScriptPath(SnortConfig *sc, const char *args)
{
    if ( sc && args )
        sc->script_path = SnortStrdup(args);
}

void config_syslog(SnortConfig* sc, const char*)
{
    static bool syslog_configured = false;

    if (syslog_configured)
        return;

    /* If daemon or logging to syslog use "snort" as identifier and
     * start logging there now */
    openlog("snort", LOG_PID | LOG_CONS, LOG_DAEMON);

    sc->logging_flags |= LOGGING_FLAG__SYSLOG;
    syslog_configured = true;
}

void config_daemon(SnortConfig* sc, const char* val)
{
    static bool daemon_configured = false;

    if (daemon_configured)
        return;

    /* If daemon or logging to syslog use "snort" as identifier and
     * start logging there now */
    openlog("snort", LOG_PID | LOG_CONS, LOG_DAEMON);

    ConfigDaemon(sc, val);
    daemon_configured = true;
}

void config_alert_mode(SnortConfig* sc, const char* val)
{
    if (strcasecmp(val, ALERT_NONE) == 0)
    {
        sc->output_flags |= OUTPUT_FLAG__NO_ALERT;
        EventManager::enable_alerts(false);
    }
    else if ((strcasecmp(val, ALERT_CMG) == 0) ||
             (strcasecmp(val, ALERT_JH) == 0) ||
             (strcasecmp(val, ALERT_DJR) == 0))
    {
        sc->output = OUTPUT_CMG;
        sc->output_flags |= OUTPUT_FLAG__SHOW_DATA_LINK;
        sc->output_flags |= OUTPUT_FLAG__APP_DATA;
    }
    else if (strcasecmp(val, ALERT_AJK) == 0)
    {
        sc->output = OUTPUT_AJK;
    }
    else
        sc->output = val;
}

void config_log_mode(SnortConfig* sc, const char* val)
{
    if (strcasecmp(val, LOG_NONE) == 0)
    {
        sc->output_flags |= OUTPUT_FLAG__NO_LOG;
        set_main_hook(snort_ignore);
        EventManager::enable_logs(false);
    }
    else if (strcasecmp(val, LOG_TEXT) == 0)
    {
        set_main_hook(snort_print);
    }
    else if (strcasecmp(val, LOG_PCAP) == 0)
    {
        sc->output = OUTPUT_PCAP;
        set_main_hook(snort_log);
    }
    else
    {
        FatalError("Unknown -K option: %s\n", val);
    }
}

void config_conf(SnortConfig*, const char* val)
{
    lua_conf = val;
    SetSnortConfDir(lua_conf.c_str());
    set_main_hook(snort_inspect);
}

void SetSnortConfDir(const char* file)
{
    /* extract the config directory from the config filename */
    if ( file )
    {
        const char *path_sep = strrchr(file, '/');

        /* is there a directory seperator in the filename */
        if (path_sep != NULL)
        {
            path_sep++;  /* include path separator */
            snort_conf_dir.assign(file, path_sep - file);
        }
        else
        {
            snort_conf_dir = "./";
        }
    }
}

