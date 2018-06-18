//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 1998-2013 Sourcefire, Inc.
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
 * Adam Keeton
 * sf_vartable.c
 * 11/17/06
 *
 * Library for managing IP variables.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sf_vartable.h"
#include "sf_ip.h"
#include "sf_ipvar.h"
#include "utils/util.h"
#include "utils/util_cstring.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;

vartable_t* sfvt_alloc_table()
{
    vartable_t* table = (vartable_t*)snort_calloc(sizeof(vartable_t));

    /* ID for recognition of variables with different name, but same content
     * Start at 1, so a value of zero indicates not set.
     * This value should be incremented for each variable that hasn't been
     * identified as an alias of another variable */
    table->id = 1;

    return table;
}

static char* sfvt_expand_value(vartable_t* table, const char* value)
{
    const char* ptr, * end;
    char* tmp, * ret = nullptr;
    int retlen = 0, retsize = 0;
    int escaped = 0;

    if ((table == nullptr) || (value == nullptr))
        return nullptr;

    if (strlen(value) == 0)
        return nullptr;

    ptr = value;
    end = value + strlen(value);
    while ((ptr < end) && isspace((int)*ptr))
        ptr++;
    while ((end > ptr) && isspace((int)*(end-1)))
        end--;
    if (ptr == end)
        return nullptr;

    tmp = snort_strndup(ptr, end-ptr);

    /* Start by allocating the length of the value */
    retsize = strlen(value) + 1;
    ret = (char*)snort_calloc(retsize);

    ptr = tmp;
    end = tmp + strlen(tmp);
    while (ptr < end)
    {
        if (!escaped && (*ptr == '$'))
        {
            const char* varstart;
            char* vartmp;
            int parens = 0;
            sfip_var_t* ipvar;

            ptr++;
            if (ptr >= end)
                goto sfvt_expand_value_error;

            if (*ptr == '(')
            {
                ptr++;
                parens = 1;
            }

            varstart = ptr;
            while (ptr < end)
            {
                if (parens)
                {
                    if (*ptr == ')')
                    {
                        break;
                    }
                }
                else if (!isalnum((int)*ptr) && (*ptr != '_'))
                {
                    break;
                }

                ptr++;
            }

            if (varstart == ptr)
                goto sfvt_expand_value_error;

            vartmp = snort_strndup(varstart, ptr - varstart);
            ipvar = sfvt_lookup_var(table, vartmp);
            snort_free(vartmp);

            if (ipvar == nullptr)
                goto sfvt_expand_value_error;

            if (ipvar->value != nullptr)
            {
                if ((int)(retlen + strlen(ipvar->value)) >= retsize)
                {
                    char* tmpalloc;

                    retsize = retlen + strlen(ipvar->value) + (end - ptr) + 1;
                    tmpalloc = (char*)snort_alloc(retsize);
                    memcpy(tmpalloc, ret, retlen);
                    strncpy(tmpalloc + retlen, ipvar->value, retsize - retlen);
                    snort_free(ret);
                    retlen += strlen(ipvar->value);
                    ret = tmpalloc;
                }
            }

            if (parens)
                ptr++;

            continue;
        }

        if (*ptr == '\\')
            escaped = 1;
        else
            escaped = 0;

        ret[retlen++] = *ptr;
        ptr++;
    }

    snort_free(tmp);

    if ((retlen + 1) < retsize)
    {
        char* tmpalloc = (char*)snort_calloc(retlen + 1);
        memcpy(tmpalloc, ret, retlen);
        snort_free(ret);
        ret = tmpalloc;
    }

    ret[retlen] = 0;
    return ret;

sfvt_expand_value_error:
    snort_free(ret);
    snort_free(tmp);
    return nullptr;
}

// XXX this implementation is just used to support
// Snort's underlying implementation better
SfIpRet sfvt_define(vartable_t* table, const char* name, const char* value)
{
    char* buf;
    int len;
    sfip_var_t* ipret = nullptr;
    SfIpRet ret;

    if (!name || !value)
        return SFIP_ARG_ERR;

    len = strlen(name) + strlen(value) + 2;
    buf = (char*)snort_alloc(len);
    snort::SnortSnprintf(buf, len, "%s %s", name, value);

    ret = sfvt_add_str(table, buf, &ipret);
    if ((ret == SFIP_SUCCESS) || (ret == SFIP_DUPLICATE))
        ipret->value = sfvt_expand_value(table, value);
    snort_free(buf);
    return ret;
}

/* Adds the variable described by "str" to the table "table" */
SfIpRet sfvt_add_str(vartable_t* table, const char* str, sfip_var_t** ipret)
{
    sfip_var_t* var;
    sfip_var_t* swp;
    sfip_var_t* p;
    int ret;
    SfIpRet status = SFIP_FAILURE;

    if (!table || !str || !ipret)
        return SFIP_FAILURE;

    /* Creates the variable */
    var = sfvar_alloc(table, str, &status);
    if ( var == nullptr )
    {
        return SFIP_FAILURE;
    }

    /* If this is an alias of another var, id will be set */
    if (var->id == 0)
        var->id = table->id++;

    *ipret = var;

    /* Insertion sort */

    if (!table->head)
    {
        table->head = var;
        return SFIP_SUCCESS;
    }

    if ((ret = strcmp(var->name, table->head->name)) < 0)
    {
        var->next = table->head;
        table->head = var;
        return SFIP_SUCCESS;
    }
    /* Redefinition */
    else if (ret == 0)
    {
        var->next = table->head->next;
        sfvar_free(table->head);
        table->head = var;
        return SFIP_DUPLICATE;
    }

    /* The loop below checks table->head->next->name in the first iteration.
     * Make sure there is a table->head->next first */
    if (!table->head->next)
    {
        table->head->next = var;
        return SFIP_SUCCESS;
    }
    else if (!strcmp(var->name, table->head->next->name))
    {
        var->next = table->head->next->next;
        sfvar_free(table->head->next);
        table->head->next = var;
        return SFIP_DUPLICATE;
    }

    for (p = table->head; p->next; p=p->next)
    {
        if ((ret = strcmp(var->name, p->next->name)) < 0)
        {
            swp = p->next;
            p->next = var;
            var->next = swp;

            return SFIP_SUCCESS;
        }
        /* Redefinition */
        else if (ret == 0)
        {
            var->next = p->next->next;
            sfvar_free(p->next);
            p->next = var;
            return SFIP_DUPLICATE;
        }
    }

    p->next = var;
    return SFIP_SUCCESS;
}

/* Adds the variable described by "src" to the variable "dst",
 * using the vartable for looking variables used within "src".
 * If vartable is null variables are not supported. 
 */
SfIpRet sfvt_add_to_var(vartable_t* table, sfip_var_t* dst, const char* src)
{
    SfIpRet ret;

    if (!dst || !src)
        return SFIP_ARG_ERR;

    if ((ret = sfvar_parse_iplist(table, dst, src, 0)) == SFIP_SUCCESS)
        return sfvar_validate(dst);

    return ret;
}

/* Looks up a variable from the table by the variable's name  */
sfip_var_t* sfvt_lookup_var(vartable_t* table, const char* name)
{
    sfip_var_t* p;
    int len;
    const char* end;

    if (!table || !name)
        return nullptr;

    if (*name == '$')
        name++;

    /* XXX should I assume there will be trailing garbage or
     * should I automatically find where the variable ends? */
    for (end=name;
        *end && !isspace((int)*end) && *end != '\\' && *end != ']';
        end++)
        ;
    len = end - name;

    for (p=table->head; len && p; p=p->next)
    {
        int name_len = strlen(p->name);
        if ((len == name_len) && !strncmp(p->name, name, len))
            return p;
    }

    return nullptr;
}

void sfvt_free_table(vartable_t* table)
{
    sfip_var_t* p, * tmp;

    if (!table)
        return;

    p = table->head;
    while (p)
    {
        tmp = p->next;
        sfvar_free(p);
        p = tmp;
    }
    snort_free(table);
}


#ifdef UNIT_TEST

TEST_CASE("SfVarTable_Kitchen_Sink", "[SfVarTable]")
{
    vartable_t* table;
    sfip_var_t* var;
    snort::SfIp* ip;
    SfIpRet status;

    table = sfvt_alloc_table();

    /* Parsing tests */
    /* These are all valid */
    CHECK(sfvt_add_str(table, "foo [ 1.2.0.0/16, ffff:dead:beef::0 ] ", &var) == SFIP_SUCCESS);
    CHECK(sfvt_add_str(table, " goo [ ffff:dead:beef::0 ] ", &var) == SFIP_SUCCESS);
    CHECK(sfvt_add_str(table, " moo [ any ] ", &var) == SFIP_SUCCESS);

    /* Test variable redefine */
    CHECK(sfvt_add_str(table, " goo [ 192.168.0.1, 192.168.0.2, 192.168.255.0 255.255.248.0 ] ",
        &var) == SFIP_DUPLICATE);

    /* These should fail since it's a variable name with bogus arguments */
    CHECK(sfvt_add_str(table, " phlegm ", &var) == SFIP_FAILURE);
    CHECK(sfvt_add_str(table, " phlegm [", &var) == SFIP_FAILURE);
    CHECK(sfvt_add_str(table, " phlegm [ ", &var) == SFIP_FAILURE);
    CHECK(sfvt_add_str(table, " phlegm [sdfg ", &var) == SFIP_FAILURE);
    CHECK(sfvt_add_str(table, " phlegm [ sdfg, 12.123.1.4.5 }", &var) == SFIP_FAILURE);
    CHECK(sfvt_add_str(table, " [ 12.123.1.4.5 ]", &var) == SFIP_FAILURE);
    CHECK(sfvt_add_str(table, nullptr, &var) == SFIP_FAILURE);
    CHECK(sfvt_add_str(table, "", &var) == SFIP_FAILURE);

    /* Containment tests */
    var = sfvt_lookup_var(table, "goo");
    ip = (snort::SfIp *)snort_alloc(sizeof(snort::SfIp));
    status = ip->set("192.168.248.255");
    CHECK(SFIP_SUCCESS == status);
    CHECK((sfvar_ip_in(var, ip) == false));

    /* Check against the 'any' variable */
    var = sfvt_lookup_var(table, "moo");
    CHECK((sfvar_ip_in(var, ip) == true));

    /* Verify it's not in this variable */
    var = sfvt_lookup_var(table, "foo");
    CHECK((sfvar_ip_in(var, ip) == false));

    /* Check boundary cases */
    var = sfvt_lookup_var(table, "goo");
    snort_free(ip);
    ip = (snort::SfIp *)snort_alloc(sizeof(snort::SfIp));
    status = ip->set("192.168.0.3");
    CHECK(SFIP_SUCCESS == status);
    CHECK((sfvar_ip_in(var, ip) == false));
    snort_free(ip);
    ip = (snort::SfIp *)snort_alloc(sizeof(snort::SfIp));
    status = ip->set("192.168.0.2");
    CHECK(SFIP_SUCCESS == status);
    CHECK((sfvar_ip_in(var, ip) == true));
    snort_free(ip);

    sfvt_free_table(table);
}

#endif

