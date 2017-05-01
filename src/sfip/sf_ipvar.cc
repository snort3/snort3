//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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
 * sf_ipvar.c
 * 11/17/06
 *
 * Library for IP variables.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sf_ipvar.h"

#include "utils/util.h"

#include "sf_cidr.h"
#include "sf_vartable.h"

#define LIST_OPEN '['
#define LIST_CLOSE ']'

static SfIpRet sfvar_list_compare(sfip_node_t*, sfip_node_t*);
static inline void sfip_node_free(sfip_node_t*);
static inline void sfip_node_freelist(sfip_node_t*);

static inline sfip_var_t* _alloc_var()
{
    return (sfip_var_t*)snort_calloc(sizeof(sfip_var_t));
}

void sfvar_free(sfip_var_t* var)
{
    if (!var)
        return;

    if (var->name)
        snort_free(var->name);

    if (var->value)
        snort_free(var->value);

    if (var->mode == SFIP_LIST)
    {
        sfip_node_freelist(var->head);
        sfip_node_freelist(var->neg_head);
    }
    else if (var->mode == SFIP_TABLE)
    {
        // XXX
    }

    snort_free(var);
}

/* Allocates and returns an IP node described by 'str' */
static sfip_node_t* sfipnode_alloc(const char* str, SfIpRet* status)
{
    // FIXIT-L rename variables from ret to something with more descriptive
    // this code smell that afflicts 55 source files and all should be fixed
    sfip_node_t* ret;
    SfIpRet rc;

    if (!str)
    {
        if (status)
            *status = SFIP_ARG_ERR;
        return NULL;
    }

    ret = (sfip_node_t*)snort_calloc(sizeof(sfip_node_t));

    /* Check if this string starts with a '!', if so,
     * then the node needs to be negated */
    if (*str == '!')
    {
        str++;
        ret->flags |= SFIP_NEGATED;
    }

    while ( isspace(*str) )
        ++str;

    /* Check if this is an "any" */
    if (!strncasecmp(str, "any", 3))
    {
        /* Make sure they're not doing !any, which is meaningless */
        if (ret->flags & SFIP_NEGATED)
        {
            if (status)
                *status = SFIP_ARG_ERR;
            snort_free(ret);
            return NULL;
        }

        ret->flags |= SFIP_ANY;

        ret->ip = new SfCidr();
        if ((rc = ret->ip->set("0.0.0.0")) != SFIP_SUCCESS)
        {
            if (status)
                *status = rc;
            sfip_node_free(ret);
            return NULL;
        }

        if (status)
            *status = SFIP_SUCCESS;
    }
    else
    {
        ret->ip = new SfCidr();
        if ((rc = ret->ip->set(str)) != SFIP_SUCCESS)
        {
            if (status)
                *status = rc;
            sfip_node_free(ret);
            return NULL;
        }
    }

    /* Check if this is a negated, zeroed IP (equivalent of a "!any") */
    if (!ret->ip->is_set() && (ret->flags & SFIP_NEGATED))
    {
        if (status)
            *status = SFIP_NOT_ANY;
        sfip_node_free(ret);
        return NULL;
    }

    return ret;
}

static inline void sfip_node_free(sfip_node_t* node)
{
    if ( !node )
        return;

    if ( node->ip )
        delete node->ip;

    snort_free(node);
}

static inline void sfip_node_freelist(sfip_node_t* root)
{
    sfip_node_t* node;

    if ( !root )
        return;

    for ( node = root; node; node = root  )
    {
        root = root->next;
        sfip_node_free(node);
    }
}

static inline sfip_node_t* _sfvar_deep_copy_list(const sfip_node_t* idx)
{
    sfip_node_t* ret, * temp, * prev;

    ret = temp = NULL;

    for (; idx; idx = idx->next)
    {
        prev = temp;

        temp = (sfip_node_t*)snort_calloc(sizeof(*temp));
        temp->ip = new SfCidr();

        temp->flags = idx->flags;
        temp->addr_flags = idx->addr_flags;

        /* If it's an "any", there may be no IP object */
        if (idx->ip)
            memcpy(temp->ip, idx->ip, sizeof(*temp->ip));

        if (prev)
            prev->next = temp;
        else
            ret = temp;
    }
    return ret;
}

/* Deep copy. Returns identical, new, linked list of sfipnodes. */
static sfip_var_t* sfvar_deep_copy(const sfip_var_t* var)
{
    sfip_var_t* ret;

    if (!var)
        return NULL;

    ret = (sfip_var_t*)snort_calloc(sizeof(*ret));

    ret->mode = var->mode;
    ret->head = _sfvar_deep_copy_list(var->head);
    ret->neg_head = _sfvar_deep_copy_list(var->neg_head);

    return ret;
}

/* Deep copy of src added to dst
   Ordering is not necessarily preserved */
static SfIpRet sfvar_add(sfip_var_t* dst, sfip_var_t* src)
{
    sfip_node_t* oldhead, * oldneg, * idx;
    sfip_var_t* copiedvar;

    if (!dst || !src)
        return SFIP_ARG_ERR;

    oldhead = dst->head;
    oldneg = dst->neg_head;

    if ((copiedvar = sfvar_deep_copy(src)) == NULL)
    {
        return SFIP_ALLOC_ERR;
    }

    dst->head = copiedvar->head;
    dst->neg_head = copiedvar->neg_head;

    snort_free(copiedvar);

    if (dst->head)
    {
        for (idx = dst->head; idx->next; idx = idx->next)
            ;

        idx->next = oldhead;
    }
    else
    {
        dst->head = oldhead;
    }

    if (dst->neg_head)
    {
        for (idx = dst->neg_head; idx->next; idx = idx->next)
            ;

        idx->next = oldneg;
    }
    else
    {
        dst->neg_head = oldneg;
    }

    return SFIP_SUCCESS;
}

/* Adds the nodes in 'src' to the variable 'dst' */
/* The mismatch of types is for ease-of-supporting Snort4 and
 * Snort6 simultaneously */
static SfIpRet sfvar_add_node(sfip_var_t* var, sfip_node_t* node, int negated)
{
    sfip_node_t* p;
    sfip_node_t* swp;
    sfip_node_t** head;

    if (!var || !node)
        return SFIP_ARG_ERR;

    /* XXX */
    /* As of this writing, 11/20/06, nodes are always added to
     * the list, regardless of the mode (list or table). */

    if (negated)
        head = &var->neg_head;
    else
        head = &var->head;

    if (!(*head))
    {
        *head = node;
        return SFIP_SUCCESS;
    }

    /* "Anys" should always be inserted first
       Otherwise, check if this IP is less than the head's IP */
    if ((node->flags & SFIP_ANY) ||
        node->ip->get_addr()->compare(*(*head)->ip->get_addr()) == SFIP_LESSER)
    {
        node->next = *head;
        *head = node;
        return SFIP_SUCCESS;
    }

    /* If we're here, the head node was lesser than the new node */
    /* Before searching the list, verify there is at least two nodes.
     * (This saves an extra check during the loop below) */
    if (!(*head)->next)
    {
        (*head)->next = node;
        return SFIP_SUCCESS;
    }

    /* Insertion sort */
    for (p = *head; p->next; p=p->next)
    {
        if (node->ip->get_addr()->compare(*p->next->ip->get_addr()) == SFIP_LESSER)
        {
            swp = p->next;
            p->next = node;
            node->next = swp;

            return SFIP_SUCCESS;
        }
    }

    p->next = node;

    return SFIP_SUCCESS;

    /* XXX Insert new node into routing table */
//    sfrt_add(node->ip,
}

sfip_var_t* sfvar_create_alias(const sfip_var_t* alias_from, const char* alias_to)
{
    sfip_var_t* ret;

    if ((alias_from == NULL) || (alias_to == NULL))
        return NULL;

    ret = sfvar_deep_copy(alias_from);
    if (ret == NULL)
        return NULL;

    ret->name = snort_strdup(alias_to);
    ret->id = alias_from->id;

    return ret;
}

static int sfvar_is_alias(const sfip_var_t* one, const sfip_var_t* two)
{
    if ((one == NULL) || (two == NULL))
        return 0;

    if ((one->id != 0) && (one->id == two->id))
        return 1;
    return 0;
}

static SfIpRet sfvar_list_compare(sfip_node_t* list1, sfip_node_t* list2)
{
    int total1 = 0;
    int total2 = 0;
    char* usage;
    sfip_node_t* tmp;

    if ((list1 == NULL) && (list2 == NULL))
        return SFIP_EQUAL;

    /* Check the ip lists for count mismatch */
    for (tmp = list1; tmp != NULL; tmp = tmp->next)
        total1++;
    for (tmp = list2; tmp != NULL; tmp = tmp->next)
        total2++;
    if (total1 != total2)
        return SFIP_FAILURE;

    /* Walk first list.  For each node, check if there is an equal
     * counterpart in the second list.  This method breaks down of there are
     * duplicated nodes.  For instance, if one = {a, b} and two = {a, a}.
     * Therefore, need additional data structure[s] ('usage') to check off
     * which nodes have been accounted for already.
     *
     * Also, the lists are not necessarily ordered, so comparing
     * node-for-node won't work */

    /* Lists are of equal size */
    usage = (char*)snort_calloc(total1);

    for (tmp = list1; tmp != NULL; tmp = tmp->next)
    {
        int i, match = 0;
        sfip_node_t* tmp2;

        for (tmp2 = list2, i = 0; tmp2 != NULL; tmp2 = tmp2->next, i++)
        {
            if ((tmp->ip->get_addr()->compare(*tmp2->ip->get_addr()) == SFIP_EQUAL) && !usage[i])
            {
                match = 1;
                usage[i] = 1;
                break;
            }
        }

        if (!match)
        {
            snort_free(usage);
            return SFIP_FAILURE;
        }
    }

    snort_free(usage);
    return SFIP_EQUAL;
}

/* Check's if two variables have the same nodes */
SfIpRet sfvar_compare(const sfip_var_t* one, const sfip_var_t* two)
{
    /* If both NULL, consider equal */
    if (!one && !two)
        return SFIP_EQUAL;

    /* If one NULL and not the other, consider unequal */
    if ((one && !two) || (!one && two))
        return SFIP_FAILURE;

    if (sfvar_is_alias(one, two))
        return SFIP_EQUAL;

    if (sfvar_list_compare(one->head, two->head) == SFIP_FAILURE)
        return SFIP_FAILURE;

    if (sfvar_list_compare(one->neg_head, two->neg_head) == SFIP_FAILURE)
        return SFIP_FAILURE;

    return SFIP_EQUAL;
}

/* Support function for sfvar_parse_iplist.  Used to
 * correctly match up end brackets.
 *  (Can't just do strchr(str, ']') because of the
 *  [a, [b], c] case, and can't do strrchr because
 *  of the [a, [b], [c]] case) */
static const char* _find_end_token(const char* str)
{
    int stack = 0;

    for (; *str; str++)
    {
        if (*str == LIST_OPEN)
            stack++;
        else if (*str == LIST_CLOSE)
            stack--;

        if (!stack)
        {
            return str;
        }
    }

    return NULL;
}

/* Support function for sfvar_parse_iplist.
 *  Negates a node */
static void _negate_node(sfip_node_t* node)
{
    if (node->addr_flags & SFIP_NEGATED)
    {
        node->addr_flags &= ~SFIP_NEGATED;
        node->flags &= ~SFIP_NEGATED;
    }
    else
    {
        node->addr_flags |= SFIP_NEGATED;
        node->flags |= SFIP_NEGATED;
    }
}

/* Support function for sfvar_parse_iplist.
 *  Negates a variable */
static void _negate_lists(sfip_var_t* var)
{
    sfip_node_t* node;
    sfip_node_t* temp;

    for (node = var->head; node; node=node->next)
        _negate_node(node);

    for (node = var->neg_head; node; node=node->next)
        _negate_node(node);

    /* Swap lists */
    temp = var->head;
    var->head = var->neg_head;
    var->neg_head = temp;
}

SfIpRet sfvar_parse_iplist(vartable_t* table, sfip_var_t* var,
    const char* str, int negation)
{
    const char* end;
    char* tok;
    SfIpRet ret;
    int neg_ip;

    if (!var || !table || !str)
        return SFIP_ARG_ERR;

    while (*str)
    {
        /* Skip whitespace and leading commas */
        if (isspace((int)*str) || *str == ',')
        {
            str++;
            continue;
        }

        neg_ip = 0;

        /* Handle multiple negations */
        for (; *str == '!' or isspace(*str); str++)
        {
            if ( *str == '!' )
                neg_ip = !neg_ip;
        }

        /* Find end of this token */
        for (end = str+1;
            *end && !isspace((int)*end) && *end != LIST_CLOSE && *end != ',';
            end++)
            ;

        tok = snort_strndup(str, end - str);

        if (*str == LIST_OPEN)
        {
            char* list_tok;

            /* Find end of this list */
            if ((end = _find_end_token(str)) == NULL)
            {
                /* No trailing bracket found */
                snort_free(tok);
                return SFIP_UNMATCHED_BRACKET;
            }

            str++;
            list_tok = snort_strndup(str, end - str);

            if ((ret = sfvar_parse_iplist(table, var, list_tok,
                    negation ^ neg_ip)) != SFIP_SUCCESS)
            {
                snort_free(list_tok);
                snort_free(tok);
                return ret;
            }

            snort_free(list_tok);
        }
        else if (*str == '$')
        {
            sfip_var_t* tmp_var;
            sfip_var_t* copy_var;

            if ((tmp_var = sfvt_lookup_var(table, tok)) == NULL)
            {
                snort_free(tok);
                return SFIP_LOOKUP_FAILURE;
            }

            copy_var = sfvar_deep_copy(tmp_var);
            /* Apply the negation */
            if (negation ^ neg_ip)
            {
                /* Check for a negated "any" */
                if (copy_var->head && copy_var->head->flags & SFIP_ANY)
                {
                    snort_free(tok);
                    sfvar_free(copy_var);
                    return SFIP_NOT_ANY;
                }

                /* Check if this is a negated, zeroed IP (equivalent of a "!any") */
                if (copy_var->head && !copy_var->head->ip->is_set())
                {
                    snort_free(tok);
                    sfvar_free(copy_var);
                    return SFIP_NOT_ANY;
                }

                _negate_lists(copy_var);
            }

            sfvar_add(var, copy_var);
            sfvar_free(copy_var);
        }
        else if (*str == LIST_CLOSE)
        {
            /* This should be the last character, if not, then this is an
             * invalid extra closing bracket */
            if (!(*(str+1)))
            {
                snort_free(tok);
                return SFIP_SUCCESS;
            }

            snort_free(tok);
            return SFIP_UNMATCHED_BRACKET;
        }
        else
        {
            sfip_node_t* node;

            /* Skip leading commas */
            for (; *str == ','; str++)
                ;

            /* Check for a negated "any" */
            if (negation ^ neg_ip && !strcasecmp(tok, "any"))
            {
                snort_free(tok);
                return SFIP_NOT_ANY;
            }

            /* This should be an IP address!
               Allocate new node for this string and add it to "ret" */
            if ((node = sfipnode_alloc(tok, &ret)) == NULL)
            {
                snort_free(tok);
                return ret;
            }

            if (negation ^ neg_ip)
            {
                _negate_node(node);
            }

            /* Check if this is a negated, zeroed IP (equivalent of a "!any") */
            if (!node->ip->is_set() && (node->flags & SFIP_NEGATED))
            {
                sfip_node_free(node);
                snort_free(tok);
                return SFIP_NOT_ANY;
            }

            ret = sfvar_add_node(var, node, negation ^ neg_ip);

            if (ret != SFIP_SUCCESS )
            {
                snort_free(tok);
                return ret;
            }
        }

        snort_free(tok);
        if (*end)
            str = end + 1;
        else
            break;
    }

    return SFIP_SUCCESS;
}

SfIpRet sfvar_validate(sfip_var_t* var)
{
    sfip_node_t* idx, * neg_idx;

    if (!var->head || !var->neg_head)
        return SFIP_SUCCESS;

    for (idx = var->head; idx; idx = idx->next)
    {
        for (neg_idx = var->neg_head; neg_idx; neg_idx = neg_idx->next)
        {
            /* A smaller netmask means "less specific" */
            if ((neg_idx->ip->get_bits() <= idx->ip->get_bits()) &&
                /* Verify they overlap */
                (neg_idx->ip->contains(idx->ip->get_addr()) == SFIP_CONTAINS))
            {
                return SFIP_CONFLICT;
            }
        }
    }

    return SFIP_SUCCESS;
}

/* Allocates and returns a new variable, described by "variable". */
sfip_var_t* sfvar_alloc(vartable_t* table, const char* variable, SfIpRet* status)
{
    sfip_var_t* ret, * tmpvar;
    const char* str, * end;
    char* tmp;
    SfIpRet stat;

    if (!variable || !(*variable))
    {
        if (status)
            *status = SFIP_ARG_ERR;
        return NULL;
    }

    if ( (ret = _alloc_var()) == NULL )
    {
        if (status)
            *status = SFIP_ALLOC_ERR;
        return NULL;
    }

    /* Extract and save the variable's name
       Start by skipping leading whitespace or line continuations: '\' */
    for (str = variable; *str && (isspace((int)*str) || *str == '\\'); str++)
        ;
    if (*str == 0)  /* Didn't get anything */
    {
        if (status)
            *status = SFIP_ARG_ERR;

        sfvar_free(ret);
        return NULL;
    }

    /* Find the end of the name */
    for (end = str; *end && !isspace((int)*end) && *end != '\\'; end++)
        ;

    if (!isalnum((int)*str) && *str != '$' && *str != '!')
    {
        if (status)
            *status = SFIP_ARG_ERR;

        sfvar_free(ret);
        return NULL;
    }

    /* Set the new variable's name/key */
    if ((ret->name = snort_strndup(str, end - str)) == NULL)
    {
        if (status)
            *status = SFIP_ALLOC_ERR;

        sfvar_free(ret);
        return NULL;
    }

    /* End points to the end of the name.  Skip past it and any whitespace
     * or potential line continuations */
    str = end;
    for (; (*str != 0) && (isspace((int)*str) || (*str == '\\')); str++)
        ;
    if (*str == 0)  /* Didn't get anything */
    {
        if (status)
            *status = SFIP_ARG_ERR;

        sfvar_free(ret);
        return NULL;
    }

    /* Trim off whitespace and line continuations from the end of the string */
    end = (str + strlen(str)) - 1;
    for (; (end > str) && (isspace((int)*end) || (*end == '\\')); end--)
        ;
    end++;

    /* See if this is just an alias */
    tmp = snort_strndup(str, end - str);
    tmpvar = sfvt_lookup_var(table, tmp);
    snort_free(tmp);
    if (tmpvar != NULL)
    {
        sfip_var_t* aliased = sfvar_create_alias(tmpvar, ret->name);
        if (aliased != NULL)
        {
            if (status != NULL)
                *status = SFIP_SUCCESS;

            sfvar_free(ret);
            return aliased;
        }
    }

    /* Everything is treated as a list, even if it's one element that's not
     * surrounded by brackets */
    stat = sfvar_parse_iplist(table, ret, str, 0);
    if (status != NULL)
        *status = stat;

    if (stat != SFIP_SUCCESS)
    {
        sfvar_free(ret);
        return NULL;
    }

    if (ret->head &&
        (ret->head->flags & SFIP_ANY && ret->head->flags & SFIP_NEGATED))
    {
        if (status)
            *status = SFIP_NOT_ANY;

        sfvar_free(ret);
        return NULL;
    }

    if (sfvar_validate(ret) == SFIP_CONFLICT)
    {
        if (status)
            *status = SFIP_CONFLICT;

        sfvar_free(ret);
        return NULL;
    }

    return ret;
}

/* Support function for sfvar_ip_in  */
static inline bool sfvar_ip_in4(sfip_var_t* var, const SfIp* ip)
{
    int match;
    sfip_node_t* pos_idx, * neg_idx;

    match = 0;

    pos_idx = var->head;
    neg_idx = var->neg_head;

    if (!pos_idx)
    {
        for (; neg_idx; neg_idx = neg_idx->next)
        {
            if (neg_idx->ip->get_addr()->get_family() != AF_INET)
                continue;

            if (neg_idx->ip->fast_cont4(*ip))
                return false;
        }

        return true;
    }

    while (pos_idx)
    {
        if (neg_idx)
        {
            if (neg_idx->ip->get_addr()->get_family() == AF_INET &&
                neg_idx->ip->fast_cont4(*ip))
            {
                return false;
            }

            neg_idx = neg_idx->next;
        }
        /* No more potential negations.  Check if we've already matched. */
        else if (match)
        {
            return true;
        }

        if (!match)
        {
            if (pos_idx->ip->is_set())
            {
                if (pos_idx->ip->get_addr()->get_family() == AF_INET &&
                    pos_idx->ip->fast_cont4(*ip))
                {
                    match = 1;
                }
                else
                {
                    pos_idx = pos_idx->next;
                }
            }
            else
            {
                match = 1;
            }
        }
    }

    return false;
}

/* Support function for sfvar_ip_in  */
static inline bool sfvar_ip_in6(sfip_var_t* var, const SfIp* ip)
{
    int match;
    sfip_node_t* pos_idx, * neg_idx;

    match = 0;

    pos_idx = var->head;
    neg_idx = var->neg_head;

    if (!pos_idx)
    {
        for (; neg_idx; neg_idx = neg_idx->next)
        {
            if (neg_idx->ip->get_addr()->get_family() != AF_INET6)
                continue;

            if (neg_idx->ip->fast_cont6(*ip))
                return false;
        }

        return true;
    }

    while (pos_idx)
    {
        if (neg_idx)
        {
            if (neg_idx->ip->get_addr()->get_family() == AF_INET6 &&
                neg_idx->ip->fast_cont6(*ip))
            {
                return false;
            }

            neg_idx = neg_idx->next;
        }
        /* No more potential negations.  Check if we've already matched. */
        else if (match)
        {
            return true;
        }

        if (!match)
        {
            if (pos_idx->ip->is_set())
            {
                if (pos_idx->ip->get_addr()->get_family() == AF_INET6 &&
                    pos_idx->ip->fast_cont6(*ip))
                {
                    match = 1;
                }
                else
                {
                    pos_idx = pos_idx->next;
                }
            }
            else
            {
                match = 1;
            }
        }
    }

    return false;
}

bool sfvar_ip_in(sfip_var_t* var, const SfIp* ip)
{
    if (!var || !ip)
        return false;

    /* Since this is a performance-critical function it uses different
     * codepaths for IPv6 and IPv4 traffic, rather than the dual-stack
     * functions. */

    if (ip->get_family() == AF_INET)
    {
        return sfvar_ip_in4(var, ip);
    }
    else
    {
        return sfvar_ip_in6(var, ip);
    }
}

