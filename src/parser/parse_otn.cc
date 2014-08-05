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

#include "parse_otn.h"

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
#include <fnmatch.h>

#ifdef HAVE_DUMBNET_H
#include <dumbnet.h>
#else
#include <dnet.h>
#endif

#include "snort_bounds.h"
#include "rules.h"
#include "treenodes.h"
#include "parser.h"
#include "cmd_line.h"
#include "parse_conf.h"
#include "parse_rule.h"
#include "snort_debug.h"
#include "util.h"
#include "mstring.h"
#include "detect.h"
#include "protocols/packet.h"
#include "fpcreate.h"
#include "tag.h"
#include "signature.h"
#include "filters/sfthreshold.h"
#include "filters/sfthd.h"
#include "snort.h"
#include "asn1.h"
#include "hash/sfghash.h"
#include "sf_vartable.h"
#include "ipv6_port.h"
#include "sfip/sf_ip.h"
#include "sflsq.h"
#include "ppm.h"
#include "filters/rate_filter.h"
#include "filters/detection_filter.h"
#include "detection/sfrim.h"
#include "utils/sfportobject.h"
#include "packet_io/active.h"
#include "file_api/libs/file_config.h"
#include "framework/ips_option.h"
#include "config_file.h"
#include "keywords.h"
#include "vars.h"
#include "managers/ips_manager.h"
#include "target_based/sftarget_reader.h"

typedef void (*ParseRuleOptFunc)(SnortConfig *, RuleTreeNode *, OptTreeNode *, const char *);

struct RuleOptFunc
{
    const char *name;
    int args_required;
    int only_once;
    int set;
    ParseRuleOptFunc parse_func;
};

static void ParseOtnClassType(
    SnortConfig *sc, RuleTreeNode*,
    OptTreeNode *otn, const char *args)
{
    ClassType *class_type;

    if (args == NULL)
    {
        ParseWarning("ClassType without an argument!");
        return;
    }

    class_type = ClassTypeLookupByType(sc, args);
    if (class_type == NULL)
        ParseError("Unknown ClassType: %s", args);

    otn->sigInfo.classType = class_type;

    /* Add the class_id to class_id so we can reference it for all rules,
     * whether they have a class_id or not.  */
    otn->sigInfo.class_id = class_type->id;

    if (otn->sigInfo.priority == 0)
        otn->sigInfo.priority = class_type->priority;
}

static void ParseOtnDetectionFilter(
    SnortConfig *sc, RuleTreeNode*,
    OptTreeNode *otn, const char *args)
{
    int count_flag = 0;
    int seconds_flag = 0;
    int tracking_flag = 0;
    char **toks;
    int num_toks;
    int i;
    static THDX_STRUCT thdx;
    const char* ERR_KEY = "detection_filter";

    memset(&thdx, 0, sizeof(THDX_STRUCT));

    toks = mSplit(args, ",", 0, &num_toks, 0);

    /* Parameter Check - enough args ?*/
    if (num_toks != 3)
    {
        ParseError(ERR_PAIR_COUNT, 3);
    }

    for (i = 0; i < num_toks; i++)
    {
        char **pairs;
        int num_pairs;

        pairs = mSplit(toks[i], " \t", 0, &num_pairs, 0);
        if (num_pairs != 2)
        {
            ParseError(ERR_NOT_PAIRED);
        }

        if (strcasecmp(pairs[0], THRESHOLD_OPT__COUNT) == 0)
        {
            if ( count_flag++ )
            {
                ParseError(ERR_EXTRA_OPTION);
            }

            thdx.count = xatoup(pairs[1],"detection_filter: count");
        }
        else if (strcasecmp(pairs[0], THRESHOLD_OPT__SECONDS) == 0)
        {
            if ( seconds_flag++ )
            {
                ParseError(ERR_EXTRA_OPTION);
            }

            thdx.seconds = xatoup(pairs[1],"detection_filter: seconds");
        }
        else if (strcasecmp(pairs[0], THRESHOLD_OPT__TRACK) == 0)
        {
            if ( tracking_flag++ )
            {
                ParseError(ERR_EXTRA_OPTION);
            }

            if (strcasecmp(pairs[1], THRESHOLD_TRACK__BY_SRC) == 0)
            {
                thdx.tracking = THD_TRK_SRC;
            }
            else if (strcasecmp(pairs[1], THRESHOLD_TRACK__BY_DST) == 0)
            {
                thdx.tracking = THD_TRK_DST;
            }
            else
            {
                ParseError(ERR_BAD_VALUE);
            }
        }
        else
        {
            ParseError(ERR_BAD_OPTION);
        }

        mSplitFree(&pairs, num_pairs);
    }

    if ((count_flag + tracking_flag + seconds_flag) != 3)
    {
        ParseError(ERR_BAD_ARG_COUNT);
    }

    mSplitFree(&toks, num_toks);

    thdx.type = THD_TYPE_DETECT;

    otn->detection_filter =
        detection_filter_create(sc->detection_filter_config, &thdx);
}

static void ParseOtnGid(
    SnortConfig*, RuleTreeNode*,
    OptTreeNode *otn, const char *args)
{
    unsigned long int gid;
    char *endptr;

    if (args == NULL)
        ParseError("Gid rule option requires an argument.");

    gid = SnortStrtoul(args, &endptr, 0);
    if ((errno == ERANGE) || (*endptr != '\0'))
    {
        ParseError("Invalid argument to 'gid' rule option: %s.  "
                   "Must be a positive integer.", args);
    }

    otn->sigInfo.generator = (uint32_t)gid;
}

static void ParseOtnMessage(
    SnortConfig*, RuleTreeNode*,
    OptTreeNode *otn, const char *args)
{
    size_t i;
    int escaped = 0;
    char msg_buf[2048];  /* Arbitrary length, but should be enough */
    const char* end;

    if (args == NULL)
        ParseError("Message rule option requires an argument.");

    if (*args == '"')
    {
        /* Have to have at least quote, char, quote */
        if (strlen(args) < 3)
            ParseError("Empty argument passed to rule option 'msg'.");

        if (args[strlen(args) - 1] != '"')
        {
            ParseError("Unmatch quote in rule option 'msg'.");
        }

        /* Move past first quote and NULL terminate last quote */
        args++;
        end = args + strlen(args) - 1;

        /* If last quote is escaped, fatal error.
         * Make sure the backslash is not escaped */
        if ((args[strlen(args) - 1] == '\\') &&
            (strlen(args) > 1) && (args[strlen(args) - 2] != '\\'))
        {
            ParseError("Unmatch quote in rule option 'msg'.");
        }
    }
    else
        end = args + strlen(args);

    /* Only valid escaped chars are ';', '"' and '\' */
    /* Would be ok except emerging threats rules are escaping other chars */
    for (i = 0; (i < sizeof(msg_buf)) && (args != end);)
    {
        if (escaped)
        {
#if 0
            if ((*args != ';') && (*args != '"') && (*args != '\\'))
            {
                ParseError("Invalid escaped character in 'msg' rule "
                           "option: '%c'.  Valid characters to escape are "
                           "';', '\"' and '\\'.\n", *args);
            }
#endif

            msg_buf[i++] = *args;
            escaped = 0;
        }
        else if (*args == '\\')
        {
            escaped = 1;
        }
        else
        {
            msg_buf[i++] = *args;
        }

        args++;
    }

    if (escaped)
    {
        ParseError("Message in 'msg' rule option has invalid escape character\n");
    }

    if (i == sizeof(msg_buf))
    {
        ParseError("Message in 'msg' rule option too long.  Please limit "
                   "to %d characters.", sizeof(msg_buf));
    }

    msg_buf[i] = '\0';

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES, "Message: %s\n", msg_buf););

    otn->sigInfo.message = SnortStrdup(msg_buf);
}

/*
 * metadata may be key/value pairs or just keys
 *
 * metadata: key [=] value, key [=] value, key [=] value, key, key, ... ;
 *
 * This option may be used one or more times, with one or more key/value pairs.
 *
 * updated 8/28/06 - man
 *
 * keys:
 *
 * rule-flushing
 * rule-type
 * service
 * os
 */
static void ParseOtnMetadata(
    SnortConfig *sc, RuleTreeNode*,
    OptTreeNode *otn, const char *args)
{
    char **metadata_toks;
    int num_metadata_toks;
    int i;

    if (args == NULL)
        ParseError("Metadata rule option requires an argument.");

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES, "metadata: %s\n", args););

    metadata_toks = mSplit(args, ",", 100, &num_metadata_toks, 0);

    for (i = 0; i < num_metadata_toks; i++)
    {
        char **key_value_toks;
        int num_key_value_toks;
        char *key = NULL;
        char *value = NULL;

        /* Split on space or equals */
        key_value_toks = mSplit(metadata_toks[i], "= ", 2, &num_key_value_toks, 0);
        key = key_value_toks[0];
        if (num_key_value_toks == 2)
            value = key_value_toks[1];

        DEBUG_WRAP(
                   DebugMessage(DEBUG_CONFIGRULES, "metadata: key=%s", key);
                   if (value != NULL)
                       DebugMessage(DEBUG_CONFIGRULES, " value=%s", value);
                   DebugMessage(DEBUG_CONFIGRULES, "\n");
                  );

        /* process key/value pairs */
        if (strcasecmp(key, METADATA_KEY__RULE_TYPE) == 0)
        {
            // rule type is deprecated; parse but ignore
            if (value == NULL)
                ParseError("Metadata key '%s' requires a value.", key);

            if ( strcasecmp(value, METADATA_VALUE__MODULE) &&
                 strcasecmp(value, METADATA_VALUE__DECODE) &&
                 strcasecmp(value, METADATA_VALUE__DETECT) )
            {
                ParseError("Metadata key '%s', passed an invalid value '%s'.",
                           key, value);
            }
        }
        /* track all of the rules for each service */
        else if (strcasecmp(key, METADATA_KEY__SERVICE) == 0 )
        {
            // metadata: service http, ... ;
            if (value == NULL)
                ParseError("Metadata key '%s' requires a value.", key);

            if (otn->sigInfo.num_services >= sc->max_metadata_services)
            {
                ParseError("Too many service's specified for rule.");
            }
            else
            {
                char *svc_name;
                int svc_count = otn->sigInfo.num_services;

                if (otn->sigInfo.services == NULL)
                {
                    otn->sigInfo.services = (ServiceInfo*)SnortAlloc(sizeof(ServiceInfo) * sc->max_metadata_services);
                }

                svc_name = otn->sigInfo.services[svc_count].service = SnortStrdup(value);
                otn->sigInfo.services[svc_count].service_ordinal = FindProtocolReference(svc_name);
                if (otn->sigInfo.services[svc_count].service_ordinal == SFTARGET_UNKNOWN_PROTOCOL)
                {
                    otn->sigInfo.services[svc_count].service_ordinal = AddProtocolReference(svc_name);
                }

                otn->sigInfo.num_services++;
            }
        }
        /* track all of the rules for each os */
        else if (strcasecmp(key, METADATA_KEY__OS) == 0 )
        {
            // metadata: os = Linux:w
            //
            if (value == NULL)
                ParseError("Metadata key '%s' requires a value.", key);

            otn->sigInfo.os = SnortStrdup(value);
        }
        else
        {
            /* XXX Why not fatal error? */
            //ParseMessage("Ignoring Metadata : %s = %s", key, value);
        }

        mSplitFree(&key_value_toks, num_key_value_toks);
    }

    mSplitFree(&metadata_toks, num_metadata_toks);
}

static void ParseOtnPriority(
    SnortConfig*, RuleTreeNode*,
    OptTreeNode *otn, const char *args)
{
    unsigned long int priority;
    char *endptr;

    if (args == NULL)
        ParseError("Priority rule option requires an argument.");

    priority = SnortStrtoul(args, &endptr, 0);
    if ((errno == ERANGE) || (*endptr != '\0'))
    {
        ParseError("Invalid argument to 'gid' rule option: %s.  "
                   "Must be a positive integer.", args);
    }

    otn->sigInfo.priority = (uint32_t)priority;
}

static void ParseOtnReference(
    SnortConfig *sc, RuleTreeNode*,
    OptTreeNode *otn, const char *args)
{
    char **toks;
    int num_toks;

    if (args == NULL)
        ParseError("Reference rule option requires an argument.");

    /* 2 tokens: system, id */
    toks = mSplit(args, ",", 2, &num_toks, 0);
    if (num_toks != 2)
    {
        ParseWarning("Ignoring invalid Reference spec '%s'.", args);
        mSplitFree(&toks, num_toks);
        return;
    }

    AddReference(sc, &otn->sigInfo.refs, toks[0], toks[1]);

    mSplitFree(&toks, num_toks);
}

static void ParseOtnRem(
    SnortConfig*, RuleTreeNode*,
    OptTreeNode*, const char*)
{
}

static void ParseOtnRevision(
    SnortConfig*, RuleTreeNode*,
    OptTreeNode *otn, const char *args)
{
    unsigned long int rev;
    char *endptr;

    if (args == NULL)
        ParseError("Revision rule option requires an argument.");

    rev = SnortStrtoul(args, &endptr, 0);
    if ((errno == ERANGE) || (*endptr != '\0'))
    {
        ParseError("Invalid argument to 'rev' rule option: %s.  "
                   "Must be a positive integer.", args);
    }

    otn->sigInfo.rev = (uint32_t)rev;
}

static void ParseOtnSid(
    SnortConfig*, RuleTreeNode*,
    OptTreeNode *otn, const char *args)
{
    unsigned long int sid;
    char *endptr;

    if (args == NULL)
        ParseError("Revision rule option requires an argument.");

    sid = SnortStrtoul(args, &endptr, 0);
    if ((errno == ERANGE) || (*endptr != '\0'))
    {
        ParseError("Invalid argument to 'sid' rule option: %s.  "
                   "Must be a positive integer.", args);
    }

    otn->sigInfo.id = (uint32_t)sid;
}

static void ParseOtnSoid(
    SnortConfig*, RuleTreeNode*,
    OptTreeNode *otn, const char *args)
{
    if ( !args )
        ParseError("soid requires a value.");

#if 1
    otn->soid = strdup(args);
#else
    char *endptr;
    uint64_t long_val;

    /* args is a '|' separated pair of gid|sid representing
     * the GID/SID of the original rule.  This is used when
     * the rule is duplicated rule by a user with different
     * IP/port info.
     */
    int num_toks;
    char** toks = mSplit(args, "|", 2, &num_toks, 0);

    if (num_toks != 2)
    {
        ParseError("Invalid args for soid. Must be a pipe "
                   "(|) separated pair.");
    }
    long_val = SnortStrtoul(toks[0], &endptr, 10);

    if ((errno == ERANGE) || (*endptr != '\0') || (long_val > UINT32_MAX))
        ParseError("Bogus gid %s", toks[0]);

    otn->soid.gid = (uint32_t)long_val;
    long_val = SnortStrtoul(toks[1], &endptr, 10);

    if ((errno == ERANGE) || (*endptr != '\0') || (long_val > UINT32_MAX))
        ParseError("Bogus sid %s", toks[1]);

    otn->soid.sid = (uint32_t)long_val;
    mSplitFree(&toks, num_toks);
#endif
}

static void ParseOtnTag(
    SnortConfig*, RuleTreeNode*,
    OptTreeNode *otn, const char *args)
{
    int type = 0;
    int count = 0;
    int metric = 0;
    int packets = 0;
    int seconds = 0;
    int bytes = 0;
    int direction = 0;
    int i;
    char **toks;
    int num_toks;
    uint8_t got_count = 0;

    if (otn->tag != NULL)
        ParseError("Can only use 'tag' rule option once per rule.");

    DEBUG_WRAP(DebugMessage(DEBUG_RULES, "Parsing tag args: %s\n", args););
    toks = mSplit(args, " ,", 0, &num_toks, 0);

    if (num_toks < 3)
        ParseError("Invalid tag arguments: %s", args);

    if (strcasecmp(toks[0], TAG_OPT__SESSION) == 0)
        type = TAG_SESSION;
    else if (strcasecmp(toks[0], TAG_OPT__HOST) == 0)
        type = TAG_HOST;
    else
        ParseError("Invalid tag type: %s", toks[0]);

    for (i = 1; i < num_toks; i++)
    {
        if (!got_count)
        {
            if (isdigit((int)toks[i][0]))
            {
                long int val;
                char *endptr;

                val = SnortStrtol(toks[i], &endptr, 0);
                if ((errno == ERANGE) || (*endptr != '\0') ||
                        (val < 0) || (val > INT32_MAX))
                {
                    ParseError("Invalid argument to 'tag' rule option.  "
                            "Numbers must be between 0 and %d.", INT32_MAX);
                }

                count = (int)val;
                got_count = 1;
            }
            else
            {
                /* Check for src/dst */
                break;
            }
        }
        else
        {
            if (strcasecmp(toks[i], TAG_OPT__SECONDS) == 0)
            {
                if (metric & TAG_METRIC_SECONDS)
                    ParseError("Can only configure seconds metric to tag rule option once");
                if (!count)
                    ParseError("Tag seconds metric must have a positive count");
                metric |= TAG_METRIC_SECONDS;
                seconds = count;
            }
            else if (strcasecmp(toks[i], TAG_OPT__PACKETS) == 0)
            {
                if (metric & (TAG_METRIC_PACKETS|TAG_METRIC_UNLIMITED))
                    ParseError("Can only configure packets metric to tag rule option once");
                if (count)
                    metric |= TAG_METRIC_PACKETS;
                else
                    metric |= TAG_METRIC_UNLIMITED;
                packets = count;
            }
            else if (strcasecmp(toks[i], TAG_OPT__BYTES) == 0)
            {
                if (metric & TAG_METRIC_BYTES)
                    ParseError("Can only configure bytes metric to tag rule option once");
                if (!count)
                    ParseError("Tag bytes metric must have a positive count");
                metric |= TAG_METRIC_BYTES;
                bytes = count;
            }
            else
            {
                ParseError("Invalid tag metric: %s", toks[i]);
            }

            got_count = 0;
        }
    }

    if (!metric || got_count)
        ParseError("Invalid tag rule option: %s", args);

    if ((metric & TAG_METRIC_UNLIMITED) &&
        !(metric & (TAG_METRIC_BYTES|TAG_METRIC_SECONDS)))
    {
        ParseError("Invalid Tag options. 'packets' parameter '0' but "
                   "neither seconds or bytes specified: %s", args);
    }

    if (i < num_toks)
    {
        if (type != TAG_HOST)
            ParseError("Only tag host type can configure direction");

        if (strcasecmp(toks[i], TAG_OPT__SRC) == 0)
            direction = TAG_HOST_SRC;
        else if (strcasecmp(toks[i], TAG_OPT__DST) == 0)
            direction = TAG_HOST_DST;
        else
            ParseError("Invalid 'tag' option: %s.", toks[i]);

        i++;
    }
    else if (type == TAG_HOST)
    {
        ParseError("Tag host type must specify direction");
    }

    /* Shouldn't be any more tokens */
    if (i != num_toks)
        ParseError("Invalid 'tag' option: %s.", args);

    mSplitFree(&toks, num_toks);

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Set type: %d  metric: %x count: %d\n", type,
                            metric, count););

    otn->tag = (TagData *)SnortAlloc(sizeof(TagData));

    otn->tag->tag_type = type;
    otn->tag->tag_metric = metric;
    otn->tag->tag_seconds = seconds;
    otn->tag->tag_bytes = bytes;
    otn->tag->tag_packets = packets;
    otn->tag->tag_direction = direction;
}

static RuleOptFunc rule_options[] =
{
    { RULE_OPT__CLASSTYPE,        1, 1, 0, ParseOtnClassType },
    { RULE_OPT__DETECTION_FILTER, 1, 1, 0, ParseOtnDetectionFilter },
    { RULE_OPT__GID,              1, 1, 0, ParseOtnGid },
    { RULE_OPT__METADATA,         1, 0, 0, ParseOtnMetadata },
    { RULE_OPT__MSG,              1, 1, 0, ParseOtnMessage },
    { RULE_OPT__PRIORITY,         1, 1, 0, ParseOtnPriority },
    { RULE_OPT__REFERENCE,        1, 0, 0, ParseOtnReference },
    { RULE_OPT__REM,              1, 1, 0, ParseOtnRem },
    { RULE_OPT__REVISION,         1, 1, 0, ParseOtnRevision },
    { RULE_OPT__SID,              1, 1, 0, ParseOtnSid },
    { RULE_OPT__SOID,             1, 1, 0, ParseOtnSoid },
    { RULE_OPT__TAG,              1, 1, 0, ParseOtnTag },

    { NULL, 0, 0, 0, NULL }
};

void parse_otn_clear()
{
    RuleOptFunc* p = rule_options;

    while ( p->name )
    {
        p->set = 0;
        ++p;
    }
}

bool parse_otn(
    SnortConfig *sc, RuleTreeNode *rtn, OptTreeNode* otn,
    char* opt, char* args, const char** so_opts)
{
    RuleOptFunc* p = rule_options;

    while ( p->name )
    {
        if ( !strcasecmp(opt, p->name) )
        {
            if (p->only_once && p->set)
            {
                ParseError("Only one '%s' rule option per rule.", opt);
                return false;
            }

            if ( !args && p->args_required )
            {
                ParseError(
                    "Keyword '%s' is missing arg(s).  "
                    "Make sure you didn't forget a ':' or the "
                    "argument to this keyword.\n", opt);
                return false;
            }

            p->parse_func(sc, rtn, otn, args);
            p->set = 1;

            if ( otn->soid && !*so_opts )
            {
                *so_opts = IpsManager::get_so_options(args);

                if ( !*so_opts )
                    ParseError("SO rule %s not loaded.", args);
            }
            return true;
        }
        ++p;
    }
    return false;
}

