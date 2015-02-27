//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2012-2013 Sourcefire, Inc.
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
/*
** Author(s):  Hui Cao <hcao@sourcefire.com>
**
** NOTES
** 5.25.2012 - Initial Source Code. Hcao
*/

#include "file_config.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>

#include "main/snort_types.h"
#include "main/snort_debug.h"
#include "util.h"
#include "mstring.h"
#include "parser/parser.h"

#include "file_lib.h"
#include "file_identifier.h"

#define DEFAULT_FILE_TYPE_DEPTH 1460
#define DEFAULT_FILE_SIGNATURE_DEPTH 10485760 /*10 Mbytes*/
#define DEFAULT_FILE_SHOW_DATA_DEPTH 100
#define DEFAULT_FILE_BLOCK_TIMEOUT 86400 /*1 day*/
#define DEFAULT_FILE_LOOKUP_TIMEOUT 2 /*2 seconds*/

typedef void (* ParseFileOptFunc)(RuleInfo*, char*);

typedef struct _FileOptFunc
{
    const char* name;
    int args_required;
    int only_once;  /*the option is one per file rule*/
    ParseFileOptFunc parse_func;
} FileOptFunc;

#define FILE_OPT__TYPE              "type"
#define FILE_OPT__ID                "id"
#define FILE_OPT__VERSION           "ver"
#define FILE_OPT__CATEGORY          "category"
#define FILE_OPT__MSG               "msg"
#define FILE_OPT__REVISION          "rev"
#define FILE_OPT__CONTENT           "content"
#define FILE_OPT__OFFSET            "offset"

#define FILE_REVISION_MAX    UINT32_MAX
#define FILE_OFFSET_MAX      UINT32_MAX

static void ParseFileRuleType(RuleInfo*, char*);
static void ParseFileRuleID(RuleInfo*, char*);
static void ParseFileRuleVersion(RuleInfo*, char*);
static void ParseFileRuleCategory(RuleInfo*, char*);
static void ParseFileRuleMessage(RuleInfo*, char*);
static void ParseFileRevision(RuleInfo*, char*);
static void ParseFileContent(RuleInfo*, char*);
static void ParseFileOffset(RuleInfo*, char*);

static const FileOptFunc file_options[] =
{
    { FILE_OPT__TYPE,             1, 1, ParseFileRuleType },
    { FILE_OPT__ID,               1, 1, ParseFileRuleID },
    { FILE_OPT__VERSION,          0, 1, ParseFileRuleVersion },
    { FILE_OPT__CATEGORY,         1, 1, ParseFileRuleCategory },
    { FILE_OPT__MSG,              0, 1, ParseFileRuleMessage },
    { FILE_OPT__REVISION,         0, 1, ParseFileRevision },
    { FILE_OPT__CONTENT,          1, 0, ParseFileContent },
    { FILE_OPT__OFFSET,           1, 0, ParseFileOffset },

    { NULL, 0, 0, NULL }       /* Marks end of array */
};

/* Used for content modifiers that are used as rule options - need to get the
 * last magic which is the one they are modifying.  If there isn't a last magic
 * error that a content must be specified before the modifier */

static inline MagicData* GetLastMagic(RuleInfo* rule, const char* option)
{
    MagicData* mdata;
    MagicData* lastMagic = NULL;

    if ((rule) && (rule->magics))
    {
        for (mdata = rule->magics; mdata->next != NULL; mdata = mdata->next)
            ;
        lastMagic = mdata;
    }
    if (lastMagic == NULL)
    {
        ParseError("please place 'content' rules before '%s' modifier",
            option == NULL ? "unknown" : option);
    }
    return lastMagic;
}

static void ParseFileRuleType(RuleInfo* rule, char* args)
{
    DEBUG_WRAP(DebugMessage(DEBUG_FILE,"Type args: %s\n", args); );

    if (args == NULL)
        ParseError("type rule option requires an argument.");

    rule->type = SnortStrdup(args);
}

static void ParseFileRuleID(RuleInfo* rule, char* args)
{
    unsigned long int id;
    char* endptr;

    DEBUG_WRAP(DebugMessage(DEBUG_FILE,"ID args: %s\n", args); );

    if (args == NULL)
    {
        ParseError("ID rule option requires an argument.");
        return;
    }

    id = SnortStrtoul(args, &endptr, 0);
    if ((errno == ERANGE) || (*endptr != '\0')||(id > FILE_ID_MAX))
    {
        ParseError("invalid argument to 'id' rule option: %s.  "
            "Must be a positive integer.", args);
    }

    rule->id = (uint32_t)id;
}

static void ParseFileRuleCategory(RuleInfo* rule, char* args)
{
    DEBUG_WRAP(DebugMessage(DEBUG_FILE,"Category args: %s\n", args); );

    if (args == NULL)
        ParseError("category rule option requires an argument.");

    rule->category = SnortStrdup(args);
}

static void ParseFileRuleVersion(RuleInfo* rule, char* args)
{
    DEBUG_WRAP(DebugMessage(DEBUG_FILE,"Version args: %s\n", args); );

    if (args == NULL)
        ParseError("version rule option requires an argument.");

    rule->version = SnortStrdup(args);
}

static void ParseFileRuleMessage(RuleInfo* rule, char* args)
{
    size_t i;
    int escaped = 0;
    char msg_buf[2048];  /* Arbitrary length, but should be enough */

    if (args == NULL)
    {
        ParseError("message rule option requires an argument.");
        return;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_FILE,"Msg args: %s\n", args); );

    if (*args == '"')
    {
        /* Have to have at least quote, char, quote */
        if (strlen(args) < 3)
        {
            ParseError("empty argument passed to rule option 'msg'.");
            return;
        }

        if (args[strlen(args) - 1] != '"')
        {
            ParseError("unmatch quote in rule option 'msg'.");
            return;
        }

        /* Move past first quote and NULL terminate last quote */
        args++;
        args[strlen(args) - 1] = '\0';

        /* If last quote is escaped, fatal error.
         * Make sure the backslash is not escaped */
        if ((args[strlen(args) - 1] == '\\') &&
            (strlen(args) > 1) && (args[strlen(args) - 2] != '\\'))
        {
            ParseError("unmatch quote in rule option 'msg'.");
            return;
        }
    }

    /* Only valid escaped chars are ';', '"' and '\'
       Would be ok except emerging threats rules are escaping other chars */
    for (i = 0; (i < sizeof(msg_buf)) && (*args != '\0'); )
    {
        if (escaped)
        {
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
        ParseError("message in 'msg' rule option has invalid escape character\n");
        return;
    }

    if (i == sizeof(msg_buf))
    {
        ParseError("message in 'msg' rule option too long.  Please limit "
            "to %d characters.", sizeof(msg_buf));
        return;
    }

    msg_buf[i] = '\0';

    DEBUG_WRAP(DebugMessage(DEBUG_FILE, "Message: %s\n", msg_buf); );

    rule->message = SnortStrdup(msg_buf);
}

static void ParseFileRevision(RuleInfo* rule, char* args)
{
    unsigned long int rev;
    char* endptr;

    DEBUG_WRAP(DebugMessage(DEBUG_FILE,"Revision args: %s\n", args); );

    if (args == NULL)
    {
        ParseError("revision rule option requires an argument.");
        return;
    }

    rev = SnortStrtoul(args, &endptr, 0);
    if ((errno == ERANGE) || (*endptr != '\0') || (rev > FILE_REVISION_MAX))
    {
        ParseError("invalid argument to 'rev' rule option: %s.  "
            "Must be a positive integer.", args);
    }

    rule->rev = (uint32_t)rev;
}

static uint8_t* convertTextToHex(char* text, int* size)
{
    int i;
    char** toks;
    int num_toks;
    char hex_buf[3];
    uint8_t* hex;

    toks = mSplit(text, " ", 0, &num_toks, 0);

    if (num_toks <= 0)
    {
        ParseError("no hexmode argument.");
        return (uint8_t*)"";
    }

    hex = (uint8_t*)SnortAlloc(num_toks);
    *size = num_toks;

    memset(hex_buf, 0, sizeof(hex_buf));

    for (i = 0; i < num_toks; i++)
    {
        char* current_ptr = toks[i];
        if (2 != strlen(current_ptr))
        {
            ParseError("content hexmode argument has invalid "
                "number of hex digits.  The argument '%s' "
                "must contain a full even byte string.", current_ptr);
            free(hex);
            return (uint8_t*)"";
        }

        if (isxdigit((int)*current_ptr))
        {
            hex_buf[0] = *current_ptr;
        }
        else
        {
            ParseError("'%c' is not a valid hex value, please input hex values (0x0 - 0xF)",
                (char)*current_ptr);
            free(hex);
            return (uint8_t*)"";
        }

        current_ptr++;

        if (isxdigit((int)*current_ptr))
        {
            hex_buf[1] = *current_ptr;
        }
        else
        {
            ParseError("'%c' is not a valid hex value, please input hex values (0x0 - 0xF)",
                (char)*current_ptr);
            free(hex);
            return (uint8_t*)"";
        }
        DEBUG_WRAP(DebugMessage(DEBUG_FILE,"Hex buffer: %s\n", hex_buf); );
        hex[i] = (uint8_t)strtol(hex_buf, (char**)NULL, 16)&0xFF;
        memset(hex_buf, 0, sizeof(hex_buf));
        DEBUG_WRAP(DebugMessage(DEBUG_FILE,"Hex value: %x\n", hex[i]); );
    }
    mSplitFree(&toks, num_toks);
    return hex;
}

static void ParseFileContent(RuleInfo* rule, char* args)
{
    MagicData* predata = NULL;
    MagicData* newdata;
    char* start_ptr;
    char* end_ptr;
    char* tmp;

    if (args == NULL)
    {
        ParseError("parse file magic got null enclosed in vertical bar (|)");
        return;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_FILE,"Content args: %s\n", args); );

    while (isspace((int)*args))
        args++;

    /* find the start of the data */
    start_ptr = strchr(args, '|');
    if (start_ptr != args)
    {
        ParseError("content data needs to be enclosed in vertical bar (|)");
        return;
    }

    /* move the start up from the beggining quotes */
    start_ptr++;

    /* find the end of the data */
    end_ptr = strrchr(start_ptr, '|');

    if (end_ptr == NULL)
    {
        ParseError("content data needs to be enclosed in vertical bar (|)");
        return;
    }

    /* Move the null termination up a bit more */
    *end_ptr = '\0';

    /* Is there anything other than whitespace after the trailing
     * double quote? */
    tmp = end_ptr + 1;
    while (*tmp != '\0' && isspace ((int)*tmp))
        tmp++;

    if (strlen (tmp) > 0)
    {
        ParseError("bad data (possibly due to missing semicolon) after "
            "trailing double quote.");
        return;
    }

    if (rule->magics)
    {
        for (predata = rule->magics; predata->next != NULL; predata = predata->next)
            ;
    }

    newdata = (MagicData*)SnortAlloc(sizeof(*newdata));

    DEBUG_WRAP(DebugMessage(DEBUG_FILE,"Content args: %s\n", start_ptr); );

    newdata->content =  convertTextToHex(start_ptr, &(newdata->content_len));

    if (predata)
    {
        predata->next = newdata;
    }
    else
    {
        rule->magics = newdata;
    }
}

static void ParseFileOffset(RuleInfo* rule, char* args)
{
    unsigned long int offset;
    char* endptr;
    MagicData* mdata;

    DEBUG_WRAP(DebugMessage(DEBUG_FILE,"Offset args: %s\n", args); );

    if (args == NULL)
    {
        ParseError("offset rule option requires an argument.");
        return;
    }

    offset = SnortStrtoul(args, &endptr, 0);
    if ((errno == ERANGE) || (*endptr != '\0')|| (offset > FILE_OFFSET_MAX))
    {
        ParseError("invalid argument to 'offset' rule option: %s.  "
            "Must be a positive integer.", args);
        return;
    }
    mdata = GetLastMagic(rule, "offset");
    mdata->offset = (uint32_t)offset;
}

static void parse_options(char* option_name, char* option_args, char* configured, RuleInfo* rule)
{
    int i;
    for (i = 0; file_options[i].name != NULL; i++)
    {
        if (strcasecmp(option_name, file_options[i].name))
            continue;

        if (configured[i] && file_options[i].only_once)
        {
            ParseError("only one '%s' rule option per rule.", option_name);
            return;
        }

        if ((option_args == NULL) && file_options[i].args_required)
        {
            ParseError("no argument passed to keyword '%s'.  "
                "Make sure you didn't forget a ':' or the "
                "argument to this keyword.\n",option_name);
            return;
        }

        file_options[i].parse_func(rule, option_args);
        configured[i] = 1;
        return;
    }
    /* Unrecognized rule option */
    ParseError("unknown rule option: '%s'.", option_name);
}

#ifdef DEBUG_MSGS
static int print_rule(RuleInfo* rule)
{
    MagicData* mdata;

    if (!rule)
    {
        DebugMessage(DEBUG_FILE,"Rule is NULL!\n");
        return 0;
    }
    DebugMessage(DEBUG_FILE,"File type Id: %d\n", rule->id);
    DebugMessage(DEBUG_FILE,"File type name: %s\n", rule->type);
    DebugMessage(DEBUG_FILE,"File type Category: %s\n", rule->category);
    DebugMessage(DEBUG_FILE,"Rule revision: %d\n", rule->rev);
    DebugMessage(DEBUG_FILE,"Rule message: %s\n", rule->message);

    if (!rule->magics)
    {
        DebugMessage(DEBUG_FILE,"No megic defined in rule!\n");
    }

    for (mdata = rule->magics; mdata != NULL; mdata = mdata->next)
    {
        int i;
        int buff_size = mdata->content_len * 2 + 1;
        char* buff = (char*)SnortAlloc(buff_size);
        char* start_ptr = buff;

        DebugMessage(DEBUG_FILE,"Magic offset: %d\n", mdata->offset);
        DebugMessage(DEBUG_FILE,"Magic length: %d\n", mdata->content_len);
        for (i = 0; (i < mdata->content_len) && (buff_size > 0); i++)
        {
            int num_read;
            num_read = snprintf(start_ptr, buff_size, "%x",mdata->content[i]);
            start_ptr += num_read;
            buff_size -= num_read;
        }
        DebugMessage(DEBUG_FILE,"Magic content: %s\n", buff);
        free(buff);
    }
    return rule->id;
}

#endif

FileConfig* get_file_config(void** conf)
{
    FileConfig* file_config = NULL;
    if (!conf)
    {
        return NULL;
    }

    if (!(*conf))
    {
        file_config = (FileConfig*)SnortAlloc(sizeof(*file_config));
        *conf = file_config;
        file_config->file_type_depth = DEFAULT_FILE_TYPE_DEPTH;
        file_config->file_signature_depth = DEFAULT_FILE_SIGNATURE_DEPTH;
        file_config->file_block_timeout = DEFAULT_FILE_BLOCK_TIMEOUT;
        file_config->file_lookup_timeout = DEFAULT_FILE_LOOKUP_TIMEOUT;
        file_config->block_timeout_lookup = false;
#if defined(DEBUG_MSGS) || defined (REG_TEST)
        file_config->show_data_depth = DEFAULT_FILE_SHOW_DATA_DEPTH;
#endif
    }
    else
        file_config = (FileConfig*)(*conf);

    return file_config;
}

/*The main function for parsing rule option*/
void parse_file_rule(const char* args, void** conf)
{
    char** toks;
    int num_toks;
    int i;
    char configured[sizeof(file_options) / sizeof(FileOptFunc)];
    RuleInfo* rule;
    FileConfig* file_config = get_file_config(conf);

    if (!file_config)
    {
        return;
    }

    rule = (RuleInfo*)SnortAlloc(sizeof (*rule));
    DEBUG_WRAP(DebugMessage(DEBUG_FILE,"Loading file configuration: %s\n", args); );

    toks = mSplit(args, ";", 0, &num_toks, 0);  /* get rule option pairs */

    /* Used to determine if a rule option has already been configured
     * in the rule.  Some can only be configured once */
    memset(configured, 0, sizeof(configured));

    for (i = 0; i < num_toks; i++)
    {
        char** opts;
        int num_opts;
        char* option_args = NULL;

        DEBUG_WRAP(DebugMessage(DEBUG_FILE,"   option: %s\n", toks[i]); );

        /* break out the option name from its data */
        opts = mSplit(toks[i], ":", 2, &num_opts, '\\');

        DEBUG_WRAP(DebugMessage(DEBUG_FILE,"   option name: %s\n", opts[0]); );

        if (num_opts == 2)
        {
            option_args = opts[1];
            DEBUG_WRAP(DebugMessage(DEBUG_FILE,"   option args: %s\n", option_args); );
        }
        parse_options(opts[0], option_args, configured, rule);
        mSplitFree(&opts, num_opts);
    }

    if (file_config->FileRules[rule->id])
    {
        ParseError("file type: duplicated rule id %d defined", rule->id);
        free(rule);
        return;
    }
    file_config->FileRules[rule->id] = rule;

    DEBUG_WRAP(DebugMessage(DEBUG_FILE,"Rule parsed: %d\n", print_rule(rule)); );
    insert_file_rule(rule,file_config);
    DEBUG_WRAP(DebugMessage(DEBUG_FILE,"Total memory used for identifiers: %d\n",
        memory_usage_identifiers()); );
    mSplitFree(&toks, num_toks);
}

RuleInfo* get_rule_from_id(void* conf, uint32_t id)
{
    if (conf)
    {
        FileConfig* file_config = (FileConfig*)conf;
        return (file_config->FileRules[id]);
    }

    return NULL;
}

static void free_file_magic(MagicData* magics)
{
    if (!magics)
        return;
    free_file_magic(magics->next);
    free (magics->content);
    free (magics);
}

static void free_file_rule(RuleInfo* rule)
{
    if (!rule)
        return;
    if (rule->category)
        free (rule->category);
    if (rule->message)
        free(rule->message);
    if (rule->type)
        free (rule->type);
    if (rule->version)
        free (rule->version);
    free_file_magic(rule->magics);
    free(rule);
}

void free_file_rules(void* conf)
{
    int id;
    FileConfig* file_config = (FileConfig*)conf;

    if (!file_config)
        return;

    for (id = 0; id < FILE_ID_MAX + 1; id++)
    {
        free_file_rule (file_config->FileRules[id]);
        file_config->FileRules[id] = NULL;
    }
}

