//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
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

#include "vars.h"

#include "log/messages.h"
#include "main/snort_config.h"
#include "sfip/sf_ipvar.h"
#include "utils/util.h"
#include "utils/util_cstring.h"

#include "parse_ports.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;

//-------------------------------------------------------------------------
// var table stuff
//-------------------------------------------------------------------------

void ParsePortVar(const char* name, const char* value)
{
    PortObject* po;
    POParser pop;
    int rstat;
    PortVarTable* portVarTable = get_ips_policy()->portVarTable;

    DisallowCrossTableDuplicateVars(name, VAR_TYPE__PORTVAR);

    if ( SnortStrcasestr(value,strlen(value),"any") ) /* this allows 'any' or '[any]' */
    {
        if (strstr(value,"!"))
        {
            ParseError("illegal use of negation and 'any': %s.", value);
        }

        po = PortObjectNew();
        PortObjectSetName(po, name);
        PortObjectAddPortAny(po);
    }
    else
    {
        /* Parse the Port List info into a PortObject  */
        po = PortObjectParseString(portVarTable, &pop, name, value, 0);
        if (!po)
        {
            const char* errstr = PortObjectParseError(&pop);
            ParseAbort("PortVar Parse error: (pos=%d,error=%s)\n>>%s\n>>%*s.",
                pop.pos,errstr,value,pop.pos,"^");
        }
    }

    /* Add The PortObject to the PortList Table */
    rstat = PortVarTableAdd(portVarTable, po);
    if ( rstat < 0 )
    {
        ParseError("PortVarTableAdd failed with '%s', exiting.", po->name);
        PortObjectFree(po);
    }
    else if ( rstat > 0 )
    {
        ParseWarning(WARN_VARS, "PortVar '%s', already defined.", po->name);
        PortObjectFree(po);
    }
}

VarEntry* VarAlloc()
{
    VarEntry* pve;

    pve = (VarEntry*)snort_calloc(sizeof(VarEntry));

    return( pve);
}

int VarIsIpAddr(vartable_t* ip_vartable, const char* value)
{
    const char* tmp;

    /* empty list, consider this an IP address */
    if ((*value == '[') && (*(value+1) == ']'))
        return 1;

    while ( *value == '!' or *value == '[' or isspace(*value) )
        value++;

    /* Check for dotted-quad */
    if ( isdigit((int)*value) &&
        ((tmp = strchr(value, (int)'.')) != nullptr) &&
        ((tmp = strchr(tmp+1, (int)'.')) != nullptr) &&
        (strchr(tmp+1, (int)'.') != nullptr))
        return 1;

    /* IPv4 with a mask, and fewer than 4 fields */
    else if ( isdigit((int)*value) &&
        (strchr(value+1, (int)':') == nullptr) &&
        ((tmp = strchr(value+1, (int)'/')) != nullptr) &&
        isdigit((int)(*(tmp+1))) )
        return 1;

    /* IPv6 */
    else if ((tmp = strchr(value, (int)':')) != nullptr)
    {
        const char* tmp2;

        if ((tmp2 = strchr(tmp+1, (int)':')) == nullptr)
            return 0;

        for (tmp++; tmp < tmp2; tmp++)
            if (!isxdigit((int)*tmp))
                return 0;

        return 1;
    }
    /* Any */
    else if (!strncmp(value, "any", 3))
        return 1;

    /* Check if it's a variable containing an IP */
    else if (sfvt_lookup_var(ip_vartable, value+1) || sfvt_lookup_var(ip_vartable, value))
        return 1;

    return 0;
}

static int CheckBrackets(char* value)
{
    int num_brackets = 0;

    while ( *value == '!' or isspace(*value) )
        value++;

    if ((value[0] != '[') || value[strlen(value)-1] != ']')
    {
        /* List does not begin or end with a bracket. */
        return 0;
    }

    while ((*value != '\0') && (num_brackets >= 0))
    {
        if (*value == '[')
            num_brackets++;
        else if (*value == ']')
            num_brackets--;
        value++;
    }
    if (num_brackets != 0)
    {
        /* Mismatched brackets */
        return 0;
    }

    return 1;
}

int VarIsIpList(vartable_t* ip_vartable, const char* value)
{
    char* copy, * item;
    int item_is_ip = 1;

    copy = snort_strdup((const char*)value);

    /* Ensure that the brackets are correct. */
    if (strchr((const char*)copy, ','))
    {
        /* This is a list! */
        if (CheckBrackets(copy) == 0)
        {
            snort_free(copy);
            return 0;
        }
    }

    /* There's no need to worry about the list structure here.
     * We just strip out the IP delimiters and process each one. */
    char* lasts = nullptr;
    item = strtok_r(copy, "[],!", &lasts);
    while ((item != nullptr) && item_is_ip)
    {
        item_is_ip = VarIsIpAddr(ip_vartable, item);
        item = strtok_r(nullptr, "[],!", &lasts);
    }

    snort_free(copy);
    return item_is_ip;
}

void DisallowCrossTableDuplicateVars(const char* name, VarType var_type)
{
    IpsPolicy* dp = get_ips_policy();
    VarEntry* var_table = dp->var_table;
    PortVarTable* portVarTable = dp->portVarTable;
    vartable_t* ip_vartable = dp->ip_vartable;
    VarEntry* p = var_table;

    switch (var_type)
    {
    case VAR_TYPE__DEFAULT:
        if ( PortVarTableFind(portVarTable, name)
            || sfvt_lookup_var(ip_vartable, name) )
        {
            ParseError("can not redefine variable name %s to be of type "
                "'var'. Use a different name.", name);
        }
        break;

    case VAR_TYPE__PORTVAR:
        if ( var_table )
        {
            do
            {
                if ( strcasecmp(p->name, name) == 0 )
                {
                    ParseError("can not redefine variable name %s to be of "
                        "type 'portvar'. Use a different name.", name);
                }
                p = p->next;
            }
            while (p != var_table);
        }

        if ( sfvt_lookup_var(ip_vartable, name) )
        {
            ParseError("can not redefine variable name %s to be of type "
                "'portvar'. Use a different name.", name);
        }

        break;

    case VAR_TYPE__IPVAR:
        if ( var_table )
        {
            do
            {
                if ( strcasecmp(p->name, name) == 0 )
                {
                    ParseError("can not redefine variable name %s to be of "
                        "type 'ipvar'. Use a different name.", name);
                }

                p = p->next;
            }
            while (p != var_table);
        }

        if ( PortVarTableFind(portVarTable, name) )
        {
            ParseError("can not redefine variable name %s to be of type "
                "'ipvar'. Use a different name.", name);
        }
        break;

    default:
        /* Invalid function usage */
        break;
    }
}

void ParsePathVar(const char* name, const char* value)
{
    if (value == nullptr)
    {
        ParseAbort("bad value in variable definition.  Make sure you don't "
            "have a '$' in the var name.");
    }

    IpsPolicy* dp = get_ips_policy();
    VarEntry* var_table = dp->var_table;
    uint32_t var_id = 0;

    /* Check to see if this variable is just being aliased */
    if (var_table != nullptr)
    {
        VarEntry* tmp = var_table;

        do
        {
            /* value+1 to move past $ */
            if (strcmp(tmp->name, value+1) == 0)
            {
                var_id = tmp->id;
                break;
            }

            tmp = tmp->next;
        }
        while (tmp != var_table);
    }

    std::string expand_value = ExpandVars(value);
    value = expand_value.c_str();

    DisallowCrossTableDuplicateVars(name, VAR_TYPE__DEFAULT);

    if (var_table == nullptr)
    {
        VarEntry* p = VarAlloc();
        p->name  = snort_strdup(name);
        p->value = snort_strdup(value);

        p->prev = p;
        p->next = p;

        dp->var_table = p;

        p->id = dp->var_id++;

        return;
    }

    /* See if an existing variable is being redefined */
    VarEntry* p = var_table;

    do
    {
        if (strcasecmp(p->name, name) == 0)
        {
            if (p->value != nullptr)
                snort_free(p->value);

            p->value = snort_strdup(value);
            ParseWarning(WARN_VARS, "Var '%s' redefined\n", p->name);
            return;
        }

        p = p->next;
    }
    while (p != var_table);     /* List is circular */

    p = VarAlloc();
    p->name  = snort_strdup(name);
    p->value = snort_strdup(value);
    p->prev = var_table;
    p->next = var_table->next;
    p->next->prev = p;
    var_table->next = p;

    if (!var_id)
        p->id = dp->var_id++;
    else
        p->id = var_id;

    return;
}

void DeleteVars(VarEntry* var_table)
{
    VarEntry* q, * p = var_table;

    while (p)
    {
        q = p->next;
        if (p->name)
            snort_free(p->name);
        if (p->value)
            snort_free(p->value);
        if (p->addrset)
        {
            sfvar_free(p->addrset);
        }
        snort_free(p);
        p = q;
        if (p == var_table)
            break;  /* Grumble, it's a friggin circular list */
    }
}

const std::string VarSearch(const std::string& name)
{
    IpsPolicy* dp = get_ips_policy();
    VarEntry* var_table = dp->var_table;
    PortVarTable* portVarTable = dp->portVarTable;
    vartable_t* ip_vartable = dp->ip_vartable;
    sfip_var_t* ipvar;

    if ((ipvar = sfvt_lookup_var(ip_vartable, name.c_str())) != nullptr)
        return ExpandVars(ipvar->value);

    if (PortVarTableFind(portVarTable, name.c_str()))
        return name;

    if (var_table != nullptr)
    {
        VarEntry* p = var_table;
        do
        {
            if (strcasecmp(p->name, name.c_str()) == 0)
                return p->value;
            p = p->next;
        }
        while (p != var_table);
    }

    return "";
}

const std::string ExpandVars(const std::string& input_str)
{
    std::stringstream output;
    bool quote_toggle = false;

    if (input_str.find('$') == std::string::npos)
        return(input_str);

    for (auto i = input_str.begin(); i < input_str.end(); i++)
    {
        const char c = *i;
        if (c == '"')
        {
            // added checks to make sure that we are inside a quoted string
            quote_toggle = !quote_toggle;
        }

        if (c == '$' && !quote_toggle)
        {
            auto begin = (i+1);
            auto end = begin;
            bool name_only = *begin != '(';
            if (!name_only)
                begin++;

            while (*end != '\0' && (
                ( name_only && (isalnum(*end) || *end == '_') ) ||
                ( !name_only && *end != ')' ) ) ) {
                end++;
            }

            std::string var_name(begin, end);
            std::string var_aux; 

            i = end;

            char var_modifier = ' ';

            size_t p = var_name.find(':');

            if (p != std::string::npos)
            {
                if (var_name.size() - p >= 2)
                {
                    var_modifier = var_name[p+1];
                    var_aux = var_name.substr(p+2);
                }
                var_name = var_name.substr(0, p);
            }

            std::string var_contents = VarSearch(var_name);

            switch (var_modifier)
            {
            case '-':
                if (var_contents.empty())
                    var_contents = var_aux.c_str();
                break;

            case '?':
                if (var_contents.empty())
                {
                    if (!var_aux.empty())
                        ParseAbort("%s", var_aux.c_str());
                    else
                        ParseAbort("undefined variable '%s'.", var_name.c_str());
                }
                break;
            }

            // If variable not defined now, we're toast
            if (var_contents.empty())
                ParseAbort("undefined variable name: %s.", var_name.c_str());

            output << var_contents;
        }
        else
        {
            output << c;
        }
    }

    return output.str();
}
