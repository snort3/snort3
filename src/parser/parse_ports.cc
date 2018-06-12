//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

#include "parse_ports.h"

#include "protocols/packet.h"
#include "utils/util.h"

using namespace snort;

static int POParserInit(POParser* pop, const char* s, PortVarTable* pvTable)
{
    memset(pop,0,sizeof(POParser));
    pop->pos     = 0;
    pop->s       = s;
    pop->slen    = strlen(s);
    pop->errflag = 0;
    pop->pvTable = pvTable;

    return 0;
}

/*
    Get a Char
*/
static int POPGetChar(POParser* pop)
{
    if ( pop->slen > 0 )
    {
        int c = pop->s[0];
        pop->slen--;
        pop->s++;
        pop->pos++;
        return c;
    }
    return 0;
}

/*
   Skip whitespace till we find a non-whitespace char
*/
static int POPGetChar2(POParser* pop)
{
    int c;
    for (;; )
    {
        c=POPGetChar(pop);
        if ( !c )
            return 0;

        if ( isspace(c) || c==',' )
            continue;

        break;
    }
    return c;
}

/*
   Restore last char
*/
static void POPUnGetChar(POParser* pop)
{
    if ( pop->pos > 0 )
    {
        pop->slen++;
        pop->s--;
        pop->pos--;
    }
}

/*
  Peek at next char
*/
static int POPPeekChar(POParser* pop)
{
    if ( pop->slen > 0)
    {
        return pop->s[0];
    }
    return 0;
}

/*
   Skip whitespace : ' ', '\t', '\n'
*/
static int POPSkipSpace(POParser* p)
{
    int c;
    for ( c  = POPPeekChar(p);
        c != 0;
        c  = POPPeekChar(p) )
    {
        if ( !isspace(c) && c != ',' )
            return c;

        POPGetChar(p);
    }
    return 0;
}

/*
  Get the Port Object Name
*/
static char* POParserName(POParser* pop)
{
    int k = 0;
    int c;

    /* check if were done  */
    if ( !pop || !pop->s || !*(pop->s) )
        return nullptr;

    /* Start the name - skip space */
    c = POPGetChar2(pop);
    if ( !c )
        return nullptr;

    if ( c== '$' ) /* skip leading '$' - old Var indicator */
    {
        c = POPGetChar2(pop);
        if ( !c )
            return nullptr;
    }

    if ( isalnum(c) )
    {
        pop->token[k++] = (char)c;
        pop->token[k]   = (char)0;
    }
    else
    {
        POPUnGetChar(pop);
        return nullptr; /* not a name */
    }

    for ( c  = POPGetChar(pop);
        c != 0 && k < POP_MAX_BUFFER_SIZE;
        c  = POPGetChar(pop) )
    {
        if ( isalnum(c) || c== '_' || c=='-' || c=='.' )
        {
            pop->token[k++] = (char)c;
            pop->token[k]   = (char)0;
        }
        else
        {
            POPUnGetChar(pop);
            break;
        }
    }

    return snort_strdup(pop->token);
}

/*
*   read an unsigned short (a port)
*/
static uint16_t POParserGetShort(POParser* pop)
{
    int c;
    int k = 0;
    char buffer[32];
    char* pend;

    POPSkipSpace(pop);

    buffer[0] = 0;

    while ( (c = POPGetChar(pop)) != 0 )
    {
        if ( isdigit(c) )
        {
            buffer[k++]=(char)c;
            buffer[k]  =0;
            if ( k == sizeof(buffer)-1 )
                break;                         /* thats all that fits */
        }
        else
        {
            if ( c && ( c!= ':' && c != ' ' && c != ']' && c != ',' && c != '\t' && c != '\n' ) )
            {
                pop->errflag = POPERR_NOT_A_NUMBER;
                return 0;
            }
            POPUnGetChar(pop);
            break;
        }
    }

    c  = (int)strtoul(buffer,&pend,10);

    if (c > 65535 || c < 0)
    {
        pop->errflag = POPERR_BOUNDS;
        return 0;
    }

    return c;
}

static PortObject* _POParseVar(POParser* pop)
{
    PortObject* pox;
    char* name;

    name  = POParserName(pop);

    if (!name)
    {
        pop->pos++;
        pop->errflag = POPERR_NO_NAME;
        return nullptr;
    }

    pox = PortVarTableFind(pop->pvTable, name);
    snort_free(name);

    if (!pox)
    {
        pop->errflag = POPERR_BAD_VARIABLE;
        return nullptr;
    }

    pox = PortObjectDup(pox);

    if (!pox)
    {
        pop->errflag = POPERR_MALLOC_FAILED;
        return nullptr;
    }

    return pox;
}

static PortObject* _POParsePort(POParser* pop)
{
    PortObject* po = PortObjectNew();

    if (!po)
    {
        pop->errflag = POPERR_MALLOC_FAILED;
        return nullptr;
    }

    pop->token[0] = 0;

    /* The string in pop should only be of the form <port> or <port>:<port> */
    uint16_t lport = POParserGetShort(pop);

    if (pop->errflag)
    {
        PortObjectFree(po);
        return nullptr;
    }

    char c = POPPeekChar(pop);

    if ( c == ':' ) /* half open range */
    {
        POPGetChar(pop);
        c = POPPeekChar(pop);
        uint16_t hport;

        if (((c == 0) && (pop->slen == 0)) ||
            (c == ','))
        {
            /* Open ended range, highport is 65k */
            hport = snort::MAX_PORTS - 1;
            PortObjectAddRange(po, lport, hport);
            return po;
        }

        if ( !isdigit((int)c) ) /* not a number */
        {
            pop->errflag = POPERR_NOT_A_NUMBER;
            PortObjectFree(po);
            return nullptr;
        }

        hport = POParserGetShort(pop);

        if ( pop->errflag )
        {
            PortObjectFree(po);
            return nullptr;
        }

        if (lport > hport)
        {
            pop->errflag = POPERR_INVALID_RANGE;
            PortObjectFree(po);
            return nullptr;
        }

        PortObjectAddRange(po, lport, hport);
    }
    else
    {
        PortObjectAddPort(po, lport);
    }

    return po;
}

// FIXIT-L _POParseString creates 1 PortObject per port in the list and
// then consolidates into one PortObject; it should just create a single
// PortObject and put each port into appropriate PortItems

static PortObject* _POParseString(POParser* pop)
{
    PortObject* po;
    PortObject* potmp = nullptr;
    int local_neg = 0;
    char c;
    int list_count = 0;

    po = PortObjectNew();

    if (!po)
    {
        pop->errflag = POPERR_MALLOC_FAILED;
        return nullptr;
    }

    while ( (c = POPGetChar2(pop)) != 0 )
    {
        if (c == '!')
        {
            local_neg = 1;
            continue;
        }

        if (c == '$')
        {
            /* Don't dup this again - the returned PortObject has already
             * been dup'ed */
            potmp = _POParseVar(pop);
        }
        /* Start of a list. Tokenize list and recurse on it */
        else if (c == '[')
        {
            POParser local_pop;
            char* tok;
            const char* end;

            list_count++;

            if ( (end = strrchr(pop->s, (int)']')) == nullptr )
            {
                pop->errflag = POPERR_NO_ENDLIST_BRACKET;
                PortObjectFree(po);
                return nullptr;
            }

            tok = snort_strndup(pop->s, end - pop->s);
            POParserInit(&local_pop, tok, pop->pvTable);

            /* Recurse */
            potmp = _POParseString(&local_pop);
            snort_free(tok);

            if (!potmp)
            {
                pop->errflag = local_pop.errflag;
                PortObjectFree(po);
                return nullptr;
            }

            /* Advance "cursor" to end of this list */
            for (; c && pop->s != end; c = POPGetChar2(pop))
                ;
        }
        else if (c == ']')
        {
            list_count--;

            if (list_count < 0)
            {
                pop->errflag = POPERR_EXTRA_BRACKET;
                PortObjectFree(po);
                return nullptr;
            }

            continue;
        }
        else
        {
            POPUnGetChar(pop);

            potmp = _POParsePort(pop);
        }

        if (!potmp)
        {
            PortObjectFree(po);
            return nullptr;
        }

        if (local_neg)
        {
            /* Note: this intentionally only sets the negation flag!
               The actual negation will take place when normalization is called */
            PortObjectToggle(potmp);

            local_neg = 0;
        }

        if (PortObjectAddPortObject(po, potmp, &pop->errflag))
        {
            PortObjectFree(po);
            PortObjectFree(potmp);
            return nullptr;
        }

        if (potmp)
        {
            PortObjectFree(potmp);
            potmp = nullptr;
        }
    }

    /* Check for mis-matched brackets */
    if (list_count)
    {
        if (list_count > 0)
            pop->errflag = POPERR_NO_ENDLIST_BRACKET;
        else
            pop->errflag = POPERR_EXTRA_BRACKET;

        PortObjectFree(po);
        return nullptr;
    }

    return po;
}

/*
*   PortObject : name value
*   PortObject : name [!][ value value value ... ]
*
*   value : [!]port
*           [!]low-port[:high-port]
*
*  inputs:
*  pvTable - PortVarTable to search for PortVar references in the current PortVar
*      pop - parsing structure
*        s - string with port object text
*
* nameflag - indicates a name must be present, this allows usage for
*            embedded rule or portvar declarations of portlists
* returns:
*      (PortObject *) - a normalized version
*/
PortObject* PortObjectParseString(PortVarTable* pvTable, POParser* pop,
    const char* name, const char* s, int nameflag)
{
    PortObject* po, * potmp;

    POParserInit(pop, s, pvTable);

    po = PortObjectNew();
    if ( !po )
    {
        pop->errflag = POPERR_MALLOC_FAILED;
        return nullptr;
    }

    if ( nameflag ) /* parse a name */
    {
        po->name = POParserName(pop);
        if ( !po->name )
        {
            pop->errflag = POPERR_NO_NAME;
            PortObjectFree(po);
            return nullptr;
        }
    }
    else
    {
        if ( name )
            po->name = snort_strdup(name);
        else
            po->name = snort_strdup("noname");
    }

    // LogMessage("PortObjectParseString: po->name=%s\n",po->name);

    potmp = _POParseString(pop);

    if ( !potmp )
    {
        PortObjectFree(po);
        return nullptr;
    }

    PortObjectNormalize(potmp);

    // Catches !:65535
    if ( sflist_count(potmp->item_list) == 0 )
    {
        PortObjectFree(po);
        PortObjectFree(potmp);
        pop->errflag = POPERR_INVALID_RANGE;
        return nullptr;
    }

    if ( PortObjectAddPortObject(po, potmp, &pop->errflag) )
    {
        PortObjectFree(po);
        PortObjectFree(potmp);
        return nullptr;
    }

    PortObjectFree(potmp);

    return po;
}

const char* PortObjectParseError(POParser* pop)
{
    switch ( pop->errflag )
    {
    case POPERR_NO_NAME:            return "no name";
    case POPERR_NO_ENDLIST_BRACKET: return "no end of list bracket."
        " Elements must be comma separated, and no spaces may appear between brackets.";
    case POPERR_NOT_A_NUMBER:       return "not a number";
    case POPERR_EXTRA_BRACKET:      return "extra list bracket";
    case POPERR_NO_DATA:            return "no data";
    case POPERR_ADDITEM_FAILED:     return "add item failed";
    case POPERR_MALLOC_FAILED:      return "mem alloc failed";
    case POPERR_INVALID_RANGE:      return "invalid port range";
    case POPERR_DUPLICATE_ENTRY:    return "duplicate ports in list";
    case POPERR_BOUNDS:             return "value out of bounds for a port";
    case POPERR_BAD_VARIABLE:       return "unrecognized variable";
    default:
        break;
    }
    return "unknown POParse error";
}

