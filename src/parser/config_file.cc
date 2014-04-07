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

#ifdef SIDE_CHANNEL
# include "side_channel/sidechannel.h"
#endif

#include "target_based/sftarget_reader.h"

// FIXIT defines should be avoided here - the actual option
// may be from command line (a-b) or from config file (a_b)
// option should be passed into all parser function for error
// messages
#define CONFIG_OPT__PAF_MAX                         "paf_max"
#define CONFIG_OPT__POLICY_VERSION                  "policy_version"
#ifdef PERF_PROFILING
# define CONFIG_OPT__PROFILE_PREPROCS               "profile_preprocs"
# define CONFIG_OPT__PROFILE_RULES                  "profile_rules"
#endif

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
            ParseError("Unknown command line checksum option: %s.", toks[i]);
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
        ParseError("Format check failed: %s,  Use format like 12:34:56:78:90:1a", s);
    }
    sc->eth_dst = (uint8_t*)SnortAlloc (sizeof(dst.data));
    memcpy(sc->eth_dst, dst.data, sizeof(dst.data));
}

/****************************************************************************
 *
 * Function: ConvPort(char *, char *)
 *
 * Purpose:  Convert the port string over to an integer value
 *
 * Arguments: port => port string
 *            proto => converted integer value of the port
 *
 * Returns:  the port number
 *
 ***************************************************************************/
static uint16_t ConvPort(const char *port, const char *proto)
{
    int conv;           /* storage for the converted number */
    const char *digit;      /* used to check for a number */
    struct servent *service_info;

    /*
     * convert a "word port" (http, ftp, imap, whatever) to its corresponding
     * numeric port value
     */
    if(isalpha((int) port[0]) != 0)
    {
        service_info = getservbyname(port, proto);

        if(service_info != NULL)
        {
            conv = ntohs(service_info->s_port);
            return conv;
        }
        else
        {
            ParseError("getservbyname() failed on '%s'.", port);
        }
    }
    digit = port;
    while (*digit) {

        if(!isdigit((int) *digit))
        {
            ParseError("Invalid port: %s.", port);
        }
        digit++;
    }
    /* convert the value */
    conv = atoi(port);

    /* make sure it's in bounds */
    if ((conv < 0) || (conv > MAXPORTS-1))
    {
        ParseError("Bad port number: %s.", port);
    }

    return (uint16_t)conv;
}

/****************************************************************************
 *
 * Function: ParsePort(SnortConfig *, char *, u_short *)
 *
 * Purpose:  Convert the port string over to an integer value
 *
 * Arguments: prule_port => port rule string
 *            port => converted integer value of the port
 *
 * Returns: 0 for a normal port number, 1 for an "any" port
 *
 ***************************************************************************/
int ParsePort(SnortConfig *sc, const char *prule_port, uint16_t *hi_port, uint16_t *lo_port, char *proto, int *not_flag)
{
    char **toks;        /* token dbl buffer */
    int num_toks;       /* number of tokens found by mSplit() */
    const char *rule_port;    /* port string */

    *not_flag = 0;

    /* check for variable */
    if(!strncmp(prule_port, "$", 1))
    {
        if((rule_port = VarGet(sc, prule_port + 1)) == NULL)
        {
            ParseError("Undefined variable %s.", prule_port);
        }
    }
    else
        rule_port = prule_port;

    if(rule_port[0] == '(')
    {
        /* user forgot to put a port number in for this rule */
        ParseError("Bad port number: '%s'.", rule_port);
    }


    /* check for wildcards */
    if(!strcasecmp(rule_port, "any"))
    {
        *hi_port = 0;
        *lo_port = 0;
        return 1;
    }

    if(rule_port[0] == '!')
    {
        if(!strcasecmp(&rule_port[1], "any"))
        {
            ParseWarning("Negating \"any\" is invalid. Rule "
                         "will be ignored.");
            return -1;
        }

        *not_flag = 1;
        rule_port++;
    }

    if(rule_port[0] == ':')
    {
        *lo_port = 0;
    }

    toks = mSplit(rule_port, ":", 2, &num_toks, 0);

    switch(num_toks)
    {
        case 1:
            *hi_port = (u_short)ConvPort(toks[0], proto);

            if(rule_port[0] == ':')
            {
                *lo_port = 0;
            }
            else
            {
                *lo_port = *hi_port;

                if(strchr(rule_port, ':') != NULL)
                {
                    *hi_port = MAXPORTS-1;
                }
            }

            break;

        case 2:
            *lo_port = (u_short)ConvPort(toks[0], proto);

            if(toks[1][0] == 0)
                *hi_port = MAXPORTS-1;
            else
                *hi_port = (u_short)ConvPort(toks[1], proto);

            break;

        default:
            ParseError("Port conversion failed on '%s'.", rule_port);
    }

    mSplitFree(&toks, num_toks);

    return 0;
}

/****************************************************************************
 *
 * Purpose: Parses a list of ports.
 *          The protocol should be "udp" or "tcp".
 *          The ports list should be a list of numbers or pairs of numbers.
 *          Each element of the list is separated by a space character.
 *          Each pair of numbers is separated by a colon character.
 *          So the string passed in is e.g. "tcp 443 578 6667:6681 13456"
 *          The numbers do not have to be in numerical order.
 *
 * Returns: void function
 *
 *****************************************************************************/
void ConfigIgnorePorts(SnortConfig *sc, int protocol, const char *ports)
{
    char ** toks;
    int     num_toks = 0;
    int     i, p;
    uint16_t hi_port = 0, lo_port = 0;
    int     not_flag;

    if ((ports == NULL))
        return;

    toks = mSplit(ports, " \t", 0, &num_toks, 0);

    if ( !num_toks )
        ParseError("config ignore_ports: Empty port list.");

    for ( i = 1; i < num_toks; i++ )
    {
        /*  Re-use function from rules processing  */
        ParsePort(sc, toks[i], &hi_port, &lo_port, toks[0], &not_flag);

        for ( p = lo_port; p <= hi_port; p++ )
        {
            if (protocol == IPPROTO_TCP)
                sc->ignore_ports[p] |= PROTO_BIT__TCP;
            else if (protocol == IPPROTO_UDP)
                sc->ignore_ports[p] |= PROTO_BIT__UDP;
        }
    }

    mSplitFree(&toks, num_toks);
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
        ParseError("Setting DAQ to %s but %s already selected.",
            args, sc->daq_type);

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
            ParseError("can't allocate memory for daq_var '%s'.", args);
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
            ParseError("can't allocate memory for daq_dir '%s'.", args);
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

void ConfigPerfFile(SnortConfig *sc, const char *args)
{
    if ( !args )
        return;

    sc->perf_file = SnortStrdup(args);
}

#define MIN_SNAPLEN  68
#define MAX_SNAPLEN  UINT16_MAX

void ConfigPacketSnaplen(SnortConfig *sc, const char *args)
{
    char *endptr;
    uint32_t snaplen;

    if ( !args )
        return;

    snaplen = SnortStrtoul(args, &endptr, 0);

    if ((errno == ERANGE) || (*endptr != '\0') ||
        ((snaplen != 0) && (snaplen < MIN_SNAPLEN)) ||
        (snaplen > MAX_SNAPLEN) )
    {
        ParseError("Invalid snaplen: %s.  Snaplen must be between "
                   "%u and %u inclusive or 0 for default = %u.",
                   args, MIN_SNAPLEN, MAX_SNAPLEN, DAQ_GetSnapLen());
    }

    sc->pkt_snaplen = snaplen;

    DEBUG_WRAP(DebugMessage(DEBUG_INIT,
        "Snap length of packets set to: %d\n", sc->pkt_snaplen););
}

void ConfigPidPath(SnortConfig *sc, const char *args)
{
    if ( !args )
        return;

    LogMessage("Found pid path directive (%s)\n", args);

    sc->run_flags |= RUN_FLAG__CREATE_PID_FILE;
    if (SnortStrncpy(sc->pid_path, args, sizeof(sc->pid_path)) != SNORT_STRNCPY_SUCCESS)
        ParseError("Pid path too long.");

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Pid Path directory = %s\n",
                            sc->pid_path););
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
        ParseError("Unknown command line policy mode option: %d.", mode);
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
                ParseError("Group '%s' unknown.", args);

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
            ParseError("Group id '%s' out of range.", args);
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
                ParseError("User '%s' unknown.", args);

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
            ParseError("User id '%s' out of range.", args);

        /* Set group id to user's default group if not
         * already set */
        if (sc->group_id == -1)
        {
            struct passwd *pw = getpwuid((uid_t)sc->user_id);  // main thread only

            if (pw == NULL)
                ParseError("User '%s' unknown.", args);

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

void ConfigSoRuleMemcap(SnortConfig *sc, const char *args)
{
    char *endptr;

    if ( !args )
        return;

    sc->so_rule_memcap = SnortStrtoul(args, &endptr, 0);
    if ((errno == ERANGE) || (*endptr != '\0'))
    {
        ParseError("Invalid so rule memcap: %s.  Memcap must be between "
                   "0 and %u inclusive.", args, UINT32_MAX);
    }
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
        ParseError("Bad umask: %s", args);
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
            ParseError("Unknown tunnel bypass protocol");

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

