//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2007-2013 Sourcefire, Inc.
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

/**
**  @file        sp_cvs.c
**
**  @author      Taimur Aslam
**  @author      Todd Wease
**
**  @brief       Decode and detect CVS vulnerabilities
**
**  This CVS detection plugin provides support for detecting published CVS vulnerabilities. The
**  vulnerabilities that can be detected are:
**  Bugtraq-10384, CVE-2004-0396: "Malformed Entry Modified and Unchanged flag insertion"
**
**  Detection Functions:
**
**  cvs: invalid-entry;
**
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hashfcn.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

using namespace snort;

static THREAD_LOCAL ProfileStats cvsPerfStats;

#define s_name "cvs"

#define CVS_CONFIG_DELIMITERS  " \t\n"

#define CVS_COMMAND_DELIMITER  '\n'
#define CVS_COMMAND_SEPARATOR  ' '

#define CVS_CONF_INVALID_ENTRY_STR  "invalid-entry"

#define CVS_NO_ALERT  0
#define CVS_ALERT     1

#define CVS_ENTRY_STR  "Entry"
#define CVS_ENTRY_VALID   0
#define CVS_ENTRY_INVALID 1

/* the types of vulnerabilities it will detect */
typedef enum _CvsTypes
{
    CVS_INVALID_ENTRY = 1,
    CVS_END_OF_ENUM
} CvsTypes;

typedef struct _CvsRuleOption
{
    CvsTypes type;
} CvsRuleOption;

/* represents a CVS command with argument */
typedef struct _CvsCommand
{
    const uint8_t* cmd_str;         /* command string */
    int cmd_str_len;
    const uint8_t* cmd_arg;         /* command argument */
    int cmd_arg_len;
} CvsCommand;

static int CvsDecode(const uint8_t*, uint16_t, CvsRuleOption*);
static void CvsGetCommand(const uint8_t*, const uint8_t*, CvsCommand*);
static int CvsCmdCompare(const char*, const uint8_t*, int);
static int CvsValidateEntry(const uint8_t*, const uint8_t*);
static void CvsGetEOL(const uint8_t*, const uint8_t*,
    const uint8_t**, const uint8_t**);

class CvsOption : public IpsOption
{
public:
    CvsOption(const CvsRuleOption& c) :
        IpsOption(s_name)
    { config = c; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

private:
    CvsRuleOption config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t CvsOption::hash() const
{
    uint32_t a,b,c;
    const CvsRuleOption* data = &config;

    a = data->type;
    b = 0;
    c = 0;

    mix_str(a,b,c,get_name());
    finalize(a,b,c);

    return c;
}

bool CvsOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    const CvsOption& rhs = (const CvsOption&)ips;
    const CvsRuleOption* left = &config;
    const CvsRuleOption* right = &rhs.config;

    if (left->type == right->type)
    {
        return true;
    }

    return false;
}

IpsOption::EvalStatus CvsOption::eval(Cursor&, Packet* p)
{
    if ( !p->has_tcp_data() )
        return NO_MATCH;

    int ret = CvsDecode(p->data, p->dsize, &config);

    if (ret == CVS_ALERT)
        return MATCH;

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// helper methods
//-------------------------------------------------------------------------

static int CvsDecode(const uint8_t* data, uint16_t data_len,
    CvsRuleOption* cvs_rule_option)
{
    const uint8_t* line, * end;
    const uint8_t* eol = nullptr, * eolm = nullptr;
    CvsCommand command;
    int ret;

    line = data;
    end = data + data_len;

    /* loop through data, analyzing a line at a time */
    while (line < end)
    {
        /* CVS commands are delimited by \n so break them up */
        CvsGetEOL(line, end, &eol, &eolm);

        /* Put command and argument into structure */
        CvsGetCommand(line, eolm, &command);

        /* shouldn't happen as long as line < end, but ... */
        if (command.cmd_str == nullptr)
            return CVS_NO_ALERT;

        switch (cvs_rule_option->type)
        {
        case CVS_INVALID_ENTRY:
            if (CvsCmdCompare(CVS_ENTRY_STR, command.cmd_str, command.cmd_str_len) == 0)
            {
                ret = CvsValidateEntry(command.cmd_arg,
                    (command.cmd_arg + command.cmd_arg_len));

                if ((ret == CVS_ENTRY_INVALID)&&(eol < end))
                {
                    return CVS_ALERT;
                }
            }

            break;

        default:
            break;
        }

        line = eol;
    }

    return CVS_NO_ALERT;
}

/*
**  NAME
**    CvsCmdCompare
**       Compares two pointers to char to see if they are equal.
**       The first arg is NULL terminated.  The second is not and
**       it's length is passed in.
**
*/
/**
**  @return 0 if equal
**  @return 1 if not equal
**
*/

static int CvsCmdCompare(const char* cmd, const uint8_t* pkt_cmd, int pkt_cmd_len)
{
    if (((size_t)pkt_cmd_len == strlen(cmd)) &&
        (memcmp(pkt_cmd, cmd, pkt_cmd_len) == 0))
    {
        return 0;
    }

    return 1;
}

/*
**  NAME
**    CvsGetCommand
**       Takes a line and breaks it up into command and argument.
**       It modifies the data in the string by replacing the first
**       space character it sees with '\0'.  A pointer to the string
**       created by the replacement is put in the CvsCommand structure's
**       command member.  A pointer to the rest of the string after
**       the replacement '\0' is put into the structure's command
**       argument member.  If there isn't a space, the entire line
**       is put in the command and the command argument is set to
**       NULL.
**
*/
/**
**  @return None
**
*/

static void CvsGetCommand(const uint8_t* line, const uint8_t* end, CvsCommand* cmd)
{
    const uint8_t* cmd_end;

    if (cmd == nullptr)
        return;

    /* no line, no command or args */
    if (line == nullptr)
    {
        cmd->cmd_str = nullptr;
        cmd->cmd_str_len = 0;
        cmd->cmd_arg = nullptr;
        cmd->cmd_arg_len = 0;

        return;
    }

    cmd->cmd_str = line;

    cmd_end = (const uint8_t*)memchr(line, CVS_COMMAND_SEPARATOR, end - line);
    if (cmd_end != nullptr)
    {
        cmd->cmd_str_len = cmd_end - line;
        cmd->cmd_arg = cmd_end + 1;
        cmd->cmd_arg_len = end - cmd_end - 1;
    }
    else
    {
        cmd->cmd_str_len = end - line;
        cmd->cmd_arg = nullptr;
        cmd->cmd_arg_len = 0;
    }
}

/*
**  NAME
**    CvsValidateEntry
**       Checks Entry argument to make sure it is well formed
**       An entry sent to the server should look like:
**       /file/version///
**       e.g. '/cvs.c/1.5///'
**       There should be nothing between the third and
**       fourth slashes
**
*/
/**
**  @return CVS_ENTRY_VALID if valid
**  @return CVS_ENTRY_INVALID if invalid
**
*/

static int CvsValidateEntry(const uint8_t* entry_arg, const uint8_t* end_arg)
{
    int slashes = 0;

    if ((entry_arg == nullptr) || (end_arg == nullptr))
    {
        return CVS_ENTRY_VALID;
    }

    /* There should be exactly 5 slashes in the string */
    while (entry_arg < end_arg)
    {
        /* if on the 3rd slash, check for next char == '/' or '+'
         * This is where the heap overflow on multiple Is-Modified
         * commands occurs */
        if (slashes == 3)
        {
            if ((*entry_arg != '/')&&(*entry_arg != '+'))
            {
                return CVS_ENTRY_INVALID;
            }
        }
        if (*entry_arg != '/')
        {
            entry_arg = (uint8_t*)memchr(entry_arg, '/', end_arg - entry_arg);
            if (entry_arg == nullptr)
                break;
        }

        slashes++;
        entry_arg++;
    }

    if (slashes != 5)
    {
        return CVS_ENTRY_INVALID;
    }

    return CVS_ENTRY_VALID;
}

/*
**       Gets a line from the data string.
**       Sets an end-of-line marker to point to the marker
**       and an end-of-line pointer to point after marker
**
*/

static void CvsGetEOL(const uint8_t* ptr, const uint8_t* end,
    const uint8_t** eol, const uint8_t** eolm)
{
    *eolm = (uint8_t*)memchr(ptr, CVS_COMMAND_DELIMITER, end - ptr);
    if (*eolm == nullptr)
    {
        *eolm = end;
        *eol = end;
    }
    else
    {
        *eol = *eolm + 1;
    }
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { CVS_CONF_INVALID_ENTRY_STR, Parameter::PT_IMPLIED, nullptr, nullptr,
      "looks for an invalid Entry string" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "payload rule option for detecting specific attacks"

class CvsModule : public Module
{
public:
    CvsModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &cvsPerfStats; }

    Usage get_usage() const override
    { return DETECT; }

public:
    CvsRuleOption data;
};

bool CvsModule::begin(const char*, int, SnortConfig*)
{
    memset(&data, 0, sizeof(data));
    return true;
}

bool CvsModule::set(const char*, Value& v, SnortConfig*)
{
    if ( !v.is(CVS_CONF_INVALID_ENTRY_STR) )
        return false;

    data.type = CVS_INVALID_ENTRY;
    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new CvsModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* cvs_ctor(Module* p, OptTreeNode*)
{
    CvsModule* m = (CvsModule*)p;
    return new CvsOption(m->data);
}

static void cvs_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi cvs_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, 0,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    cvs_ctor,
    cvs_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* ips_cvs[] =
#endif
{
    &cvs_api.base,
    nullptr
};

