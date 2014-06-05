/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
** Copyright (C) 2000,2001 Andrew R. Baker <andrewb@uab.edu>
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

#include "parse_conf.h"

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

#include <stack>
#include <string>
#include <sstream>
using namespace std;

#include "snort_bounds.h"
#include "rules.h"
#include "treenodes.h"
#include "parser.h"
#include "cmd_line.h"
#include "parse_rule.h"
#include "snort_debug.h"
#include "util.h"
#include "mstring.h"
#include "fpcreate.h"
#include "signature.h"
#include "snort.h"
#include "hash/sfghash.h"
#include "sf_vartable.h"
#include "ipv6_port.h"
#include "sfip/sf_ip.h"
#include "utils/sfportobject.h"
#include "packet_io/active.h"
#include "file_api/libs/file_config.h"
#include "framework/ips_option.h"
#include "actions/actions.h"
#include "config_file.h"
#include "keywords.h"
#include "vars.h"

struct Location
{
    string file;
    unsigned line;

    Location(const char* s, unsigned u)
    { file = s; line = u; };
};

static stack<Location> files;

const char* get_parse_file()
{
    if ( files.empty() )
        return nullptr;

    Location& loc = files.top();
    return loc.file.c_str();
}

void get_parse_location(const char*& file, unsigned& line)
{
    if ( files.empty() )
    {
        file = nullptr;
        line = 0;
        return;
    }
    Location& loc = files.top();
    file = loc.file.c_str();
    line = loc.line;
}
    
void push_parse_location(const char* file, unsigned line)
{
    if ( !file )
        return;

    Location loc(file, line);
    files.push(loc);
}

void pop_parse_location()
{
    if ( !files.empty() )
        files.pop();
}

static void inc_parse_position()
{
    Location& loc = files.top();
    ++loc.line;
}

static bool s_parse_rules = false;
static void ParseTheConf(SnortConfig*, const char* fname);

/* Used to determine whether or not to parse the keyword line based on
 * whether or not we're parsing rules */
typedef enum _KeywordType
{
    KEYWORD_TYPE__MAIN,
    KEYWORD_TYPE__RULE,
    KEYWORD_TYPE__ALL

} KeywordType;

typedef void (*ParseFunc)(SnortConfig *, const char *);

typedef struct _KeywordFunc
{
    const char *name;
    KeywordType type;
    int expand_vars;
    int default_policy_only;
    ParseFunc parse_func;

} KeywordFunc;

// only keep drop rules ...
// if we are inline (and can actually drop),
// or we are going to just alert instead of drop,
// or we are going to ignore session data instead of drop.
// the alert case is tested for separately with ScTreatDropAsAlert().
static inline int ScKeepDropRules (void)
{
    return ( ScInlineMode() || ScAdapterInlineMode() || ScTreatDropAsIgnore() );
}

static inline int ScLoadAsDropRules (void)
{
    return ( ScInlineTestMode() || ScAdapterInlineTestMode() );
}

static void ParseAlert(SnortConfig *sc, const char *args)
{
    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES, "Alert\n"););
    parse_rule(sc, args, RULE_TYPE__ALERT, &sc->Alert);
}

static void ParseDrop(SnortConfig *sc, const char *args)
{
    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Drop\n"););

    /* Parse as an alert if we're treating drops as alerts */
    if (ScTreatDropAsAlert())
        parse_rule(sc, args, RULE_TYPE__ALERT, &sc->Alert);

    else if ( ScKeepDropRules() || ScLoadAsDropRules() )
        parse_rule(sc, args, RULE_TYPE__DROP, &sc->Drop);
}

static void ParseLog(SnortConfig *sc, const char *args)
{
    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES, "Log\n"););
    parse_rule(sc, args, RULE_TYPE__LOG, &sc->Log);
}

static void ParsePass(SnortConfig *sc, const char *args)
{
    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES, "Pass\n"););
    parse_rule(sc, args, RULE_TYPE__PASS, &sc->Pass);
}

static void ParseReject(SnortConfig *sc, const char *args)
{
    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES, "Reject\n"););
    parse_rule(sc, args, RULE_TYPE__REJECT, &sc->Reject);
    Active_SetEnabled(1);
}

static void ParseSdrop(SnortConfig *sc, const char *args)
{
    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES, "SDrop\n"););

    if ( ScKeepDropRules() && !ScTreatDropAsAlert() )
        parse_rule(sc, args, RULE_TYPE__SDROP, &sc->SDrop);
}

void ParseInclude(SnortConfig *sc, const char *arg)
{
    struct stat file_stat;  /* for include path testing */
    char* fname = SnortStrdup(arg);

    /* Stat the file.  If that fails, stat it relative to the directory
     * that the top level snort configuration file was in */
    if (stat(fname, &file_stat) == -1)
    {
        const char* snort_conf_dir = get_snort_conf_dir();

        int path_len = strlen(snort_conf_dir) + strlen(arg) + 1;

        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"ParseInclude: stat "
                                "on %s failed - going to config_dir\n", fname););

        free(fname);

        fname = (char *)SnortAlloc(path_len);
        snprintf(fname, path_len, "%s%s", snort_conf_dir, arg);

        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"ParseInclude: Opening "
                                "and parsing %s\n", fname););
    }

    push_parse_location(fname);
    ParseTheConf(sc, fname);
    pop_parse_location();
    free((char*)fname);
}

void ParseIpVar(SnortConfig *sc, const char* var, const char* val)
{
    int ret;
    IpsPolicy* p = get_ips_policy(); // FIXIT double check, see below
    DisallowCrossTableDuplicateVars(sc, var, VAR_TYPE__IPVAR);

    if((ret = sfvt_define(p->ip_vartable, var, val)) != SFIP_SUCCESS)
    {
        switch(ret) {
            case SFIP_ARG_ERR:
                ParseError("The following is not allowed: %s.", val);
                break;

            case SFIP_DUPLICATE:
                ParseMessage("Var '%s' redefined.", var);
                break;

            case SFIP_CONFLICT:
                ParseError("Negated IP ranges that are more general than "
                        "non-negated ranges are not allowed. Consider "
                        "inverting the logic in %s.", var);
                break;

            case SFIP_NOT_ANY:
                ParseError("!any is not allowed in %s.", var);
                break;

            default:
                ParseError("Failed to parse the IP address: %s.", val);
        }
    }
}

// FIXIT find this a better home
void AddRuleState(SnortConfig* sc, const RuleState& rs)
{
    if (sc == NULL)
        return;

    RuleState* state = (RuleState *)SnortAlloc(sizeof(RuleState));
    *state = rs;

    if ( !sc->rule_state_list )
    {
        sc->rule_state_list = state;
    }
    else
    {
        state->next = sc->rule_state_list;
        sc->rule_state_list = state;
    }
}

static void ParseFile(SnortConfig *sc, const char *args)
{
    parse_file_rule(args, &(sc->file_config));
}

static const KeywordFunc snort_conf_keywords[] =
{
    // this stuff is expected to remain since rules don't fit in Lua tables
    // in any helpful way; include stays too since it is used to load
    // nested rules files

    // however, these must become pluggable ...
    { ACTION_ALERT,    KEYWORD_TYPE__RULE, 0, 0, ParseAlert },
    { ACTION_DROP,     KEYWORD_TYPE__RULE, 0, 0, ParseDrop },
    { ACTION_BLOCK,    KEYWORD_TYPE__RULE, 0, 0, ParseDrop },
    { ACTION_LOG,      KEYWORD_TYPE__RULE, 0, 0, ParseLog },
    { ACTION_PASS,     KEYWORD_TYPE__RULE, 0, 0, ParsePass },
    { ACTION_REJECT,   KEYWORD_TYPE__RULE, 0, 0, ParseReject },
    { ACTION_SDROP,    KEYWORD_TYPE__RULE, 0, 0, ParseSdrop },
    { ACTION_SBLOCK,   KEYWORD_TYPE__RULE, 0, 0, ParseSdrop },

    { SNORT_CONF_KEYWORD__FILE,     KEYWORD_TYPE__MAIN, 0, 1, ParseFile },
    { SNORT_CONF_KEYWORD__INCLUDE,  KEYWORD_TYPE__ALL,  1, 0, ParseInclude },

#if 0
    // this needs to be turned into an action plugin
    // the special case parsing got in the way refactoring for Lua
    // so it's toast - here for reference only

    /* Special parsing case is ruletype.  Need to send the file pointer so
     * it can parse what's between '{' and '}' which can span multiple
     * lines without a line continuation character */
    { SNORT_CONF_KEYWORD__RULE_TYPE, KEYWORD_TYPE__ALL,  1, 0, ParseRuleTypeDeclaration },
#endif

    { NULL, KEYWORD_TYPE__ALL, 0, 0, NULL }   /* Marks end of array */
};

static int ContinuationCheck(char *rule)
{
    char *idx;  /* indexing var for moving around on the string */

    idx = rule + strlen(rule) - 1;

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"initial idx set to \'%c\'\n",
                *idx););

    while(isspace((int)*idx))
    {
        idx--;
    }

    if(*idx == '\\')
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Got continuation char, "
                    "clearing char and returning 1\n"););

        /* clear the '\' so there isn't a problem on the appended string */
        *idx = '\x0';
        return 1;
    }

    return 0;
}

static void ParseConfigFileLine(SnortConfig *sc, char *buf)
{
    /* Used for line continuation */
    static int continuation = 0;
    static char *saved_line = NULL;
    static char *new_line = NULL;

        /* buffer indexing pointer */
        char *index = buf;

        /* Increment the line counter so the error messages know which
         * line to bitch about */
        inc_parse_position();

        /* fgets always appends a null, so doing a strlen should be safe */
        if ((strlen(buf) + 1) == MAX_LINE_LENGTH)
        {
            ParseError("Line greater than or equal to %u characters which is "
                       "more than the parser is willing to handle.  Try "
                       "splitting it up on multiple lines if possible.",
                       MAX_LINE_LENGTH);
        }

        /* advance through any whitespace at the beginning of the line */
        while (isspace((int)*index))
            index++;

        /* If it's an empty line or starts with a comment character */
        if ((strlen(index) == 0) || (*index == '#') || (*index == ';'))
            return;

        if (continuation)
        {
            int new_line_len = strlen(saved_line) + strlen(index) + 1;

            if (new_line_len >= PARSE_RULE_SIZE)
            {
                ParseError("Rule greater than or equal to %u characters which "
                           "is more than the parser is willing to handle.  "
                           "Submit a bug to bugs@snort.org if you legitimately "
                           "feel like your rule or keyword configuration needs "
                           "more than this amount of space.", PARSE_RULE_SIZE);
            }

            new_line = (char *)SnortAlloc(new_line_len);
            snprintf(new_line, new_line_len, "%s%s", saved_line, index);

            free(saved_line);
            saved_line = NULL;
            index = new_line;

            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"concat rule: %s\n",
                                    new_line););
        }

        /* check for a '\' continuation character at the end of the line
         * if it's there we need to get the next line in the file */
        if (ContinuationCheck(index) == 0)
        {
            char **toks;
            int num_toks;
            char *keyword;
            char *args;
            int i;

            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,
                                    "[*] Processing keyword: %s\n", index););

            /* Get the keyword and args */
            toks = mSplit(index, " \t", 2, &num_toks, 0);
            if (num_toks != 2)
                ParseError("Invalid configuration line: %s", index);

            keyword = SnortStrdup(ExpandVars(sc, toks[0]));
            args = toks[1];

            for (i = 0; snort_conf_keywords[i].name != NULL; i++)
            {
                if (strcasecmp(keyword, snort_conf_keywords[i].name) == 0)
                {
                    if (((snort_conf_keywords[i].type == KEYWORD_TYPE__RULE) &&
                         !s_parse_rules) ||
                        ((snort_conf_keywords[i].type == KEYWORD_TYPE__MAIN) &&
                         s_parse_rules))
                    {
                        break;
                    }

                    if (snort_conf_keywords[i].expand_vars)
                        args = SnortStrdup(ExpandVars(sc, toks[1]));

                    snort_conf_keywords[i].parse_func(sc, args);
                    break;
                }
            }

            /* Didn't find any pre-defined snort_conf_keywords.  Look for a user defined
             * rule type */

            if ((snort_conf_keywords[i].name == NULL) && s_parse_rules)
            {
                RuleListNode *node;

                DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES, "Unknown rule type, "
                                        "might be declared\n"););

                for (node = sc->rule_lists; node != NULL; node = node->next)
                {
                    if (strcasecmp(node->name, keyword) == 0)
                        break;
                }

                if (node == NULL)
                    ParseError("Unknown rule type: %s.", toks[0]);

                if ( node->mode == RULE_TYPE__DROP )
                {
                    if ( ScTreatDropAsAlert() )
                        parse_rule(sc, args, RULE_TYPE__ALERT, node->RuleList);

                    else if ( ScKeepDropRules() ||  ScLoadAsDropRules() )
                        parse_rule(sc, args, node->mode, node->RuleList);
                }
                else if ( node->mode == RULE_TYPE__SDROP )
                {
                    if ( ScKeepDropRules() && !ScTreatDropAsAlert() )
                        parse_rule(sc, args, node->mode, node->RuleList);

                    else if ( ScLoadAsDropRules() )
                        parse_rule(sc, args, RULE_TYPE__DROP, node->RuleList);
                }
                else
                {
                    parse_rule(sc, args, node->mode, node->RuleList);
                }
            }

            if (args != toks[1])
                free(args);

            free(keyword);
            mSplitFree(&toks, num_toks);

            if(new_line != NULL)
            {
                free(new_line);
                new_line = NULL;
                continuation = 0;
            }
        }
        else
        {
            /* save the current line */
            saved_line = SnortStrdup(index);

            /* current line was a continuation itself... */
            if (new_line != NULL)
            {
                free(new_line);
                new_line = NULL;
            }

            /* set the flag to let us know the next line is
             * a continuation line */
            continuation = 1;
        }
}

static void ParseTheConf(SnortConfig *sc, const char *fname)
{
    char *buf = (char *)SnortAlloc(MAX_LINE_LENGTH + 1);
    FILE *fp = fopen(fname, "r");

    /* open the rules file */
    if (fp == NULL)
    {
        ParseError("Unable to open rules file '%s': %s.\n",
                   fname, get_error(errno));
    }

    /* loop thru each file line and send it to the rule parser */
    while ((fgets(buf, MAX_LINE_LENGTH, fp)) != NULL)
    {
        ParseConfigFileLine(sc, buf);
    }

    fclose(fp);
    free(buf);
}

void ParseConfigString(SnortConfig* sc, const char* s, bool parse_rules)
{
    s_parse_rules = parse_rules;

    string rules = s;
    stringstream ss(rules);

    char *buf = (char *)SnortAlloc(MAX_LINE_LENGTH + 1);

    while ( ss.getline(buf, MAX_LINE_LENGTH) )
        ParseConfigFileLine(sc, buf);
        
    free(buf);
}

void ParseConfigFile(
    SnortConfig *sc, const char *fname, bool parse_rules)
{
    s_parse_rules = parse_rules;

    if ( fname )
        ParseTheConf(sc, fname);
}

