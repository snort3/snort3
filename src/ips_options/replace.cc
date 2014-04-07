/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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

#include "replace.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>

#include "snort_types.h"
#include "snort_bounds.h"
#include "snort_debug.h"
#include "decode.h"
#include "parser.h"
#include "ips_content.h"
#include "snort.h"
#include "packet_io/sfdaq.h"

#define MAX_PATTERN_SIZE 2048

static void Replace_Parse(
    char *rule, OptTreeNode*, PatternMatchData* pmd)
{
    char tmp_buf[MAX_PATTERN_SIZE];

    /* got enough ptrs for you? */
    char *start_ptr;
    char *end_ptr;
    char *idx;
    const char *dummy_idx;
    const char *dummy_end;
    char hex_buf[3];
    u_int dummy_size = 0;
    int size;
    int hexmode = 0;
    int hexsize = 0;
    int pending = 0;
    int cnt = 0;
    int literal = 0;
    int ret;

    if ( !rule )
    {
        ParseError("missing argument to 'replace' option");
    }
    /* clear out the temp buffer */
    memset(tmp_buf, 0, MAX_PATTERN_SIZE);

    while(isspace((int)*rule))
        rule++;

    /* find the start of the data */
    start_ptr = strchr(rule, '"');

    if(start_ptr == NULL)
    {
        ParseError("Replace data needs to be "
                   "enclosed in quotation marks (\")");
    }

    /* move the start up from the beggining quotes */
    start_ptr++;

    /* find the end of the data */
    end_ptr = strrchr(start_ptr, '"');

    if(end_ptr == NULL)
    {
        ParseError("Replace data needs to be enclosed "
                   "in quotation marks (\")");
    }

    /* set the end to be NULL */
    *end_ptr = '\0';

    /* how big is it?? */
    size = end_ptr - start_ptr;

    /* uh, this shouldn't happen */
    if(size <= 0)
    {
        ParseError("Replace data has bad pattern length!");
    }
    /* set all the pointers to the appropriate places... */
    idx = start_ptr;

    /* set the indexes into the temp buffer */
    dummy_idx = tmp_buf;
    dummy_end = (dummy_idx + size);

    /* why is this buffer so small? */
    memset(hex_buf, '0', 2);
    hex_buf[2] = '\0';


    /* BEGIN BAD JUJU..... */
    while(idx < end_ptr)
    {
        if (dummy_size >= MAX_PATTERN_SIZE-1)
        {
            /* Have more data to parse and pattern is about to go beyond end of buffer */
            ParseError("Replace buffer overflow, make a "
                    "smaller pattern please! (Max size = %d)",
                    MAX_PATTERN_SIZE-1);
        }

        DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "processing char: %c\n", *idx););

        switch(*idx)
        {
            case '|':

                DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "Got bar... "););

                if(!literal)
                {

                    DEBUG_WRAP(DebugMessage(DEBUG_PARSER,
                        "not in literal mode... "););

                    if(!hexmode)
                    {
                        DEBUG_WRAP(DebugMessage(DEBUG_PARSER,
                        "Entering hexmode\n"););

                        hexmode = 1;
                    }
                    else
                    {

                        DEBUG_WRAP(DebugMessage(DEBUG_PARSER,
                        "Exiting hexmode\n"););

                        hexmode = 0;
                        pending = 0;
                    }

                    if(hexmode)
                        hexsize = 0;
                }
                else
                {

                    DEBUG_WRAP(DebugMessage(DEBUG_PARSER,
                        "literal set, Clearing\n"););

                    literal = 0;
                    tmp_buf[dummy_size] = start_ptr[cnt];
                    dummy_size++;
                }

                break;

            case '\\':

                DEBUG_WRAP(DebugMessage(DEBUG_PARSER, "Got literal char... "););

                if(!literal)
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_PARSER,
                        "Setting literal\n"););

                    literal = 1;
                }
                else
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_PARSER,
                        "Clearing literal\n"););

                    tmp_buf[dummy_size] = start_ptr[cnt];
                    literal = 0;
                    dummy_size++;
                }
                break;

            default:
                if(hexmode)
                {
                    if(isxdigit((int) *idx))
                    {
                        hexsize++;

                        if(!pending)
                        {
                            hex_buf[0] = *idx;
                            pending++;
                        }
                        else
                        {
                            hex_buf[1] = *idx;
                            pending--;

                            if(dummy_idx < dummy_end)
                            {
                                tmp_buf[dummy_size] = (u_char)
                                    strtol(hex_buf, (char **) NULL, 16)&0xFF;

                                dummy_size++;
                                memset(hex_buf, '0', 2);
                                hex_buf[2] = '\0';
                            }
                            else
                            {
                                ParseError("Replace buffer overflow, make a "
                                           "smaller pattern please! (Max size = %d)",
                                           MAX_PATTERN_SIZE-1);
                            }
                        }
                    }
                    else
                    {
                        if(*idx != ' ')
                        {
                            ParseError("Replace found '%c'(0x%X) in "
                                       "your binary buffer.  Valid hex values only "
                                       "please! (0x0 -0xF) Position: %d",
                                       (char) *idx, (char) *idx, cnt);
                        }
                    }
                }
                else
                {
                    if(*idx >= 0x1F && *idx <= 0x7e)
                    {
                        if(dummy_idx < dummy_end)
                        {
                            tmp_buf[dummy_size] = start_ptr[cnt];
                            dummy_size++;
                        }
                        else
                        {
                            ParseError("Replace buffer overflow");
                        }

                        if(literal)
                        {
                            literal = 0;
                        }
                    }
                    else
                    {
                        if(literal)
                        {
                            tmp_buf[dummy_size] = start_ptr[cnt];
                            dummy_size++;

                            DEBUG_WRAP(DebugMessage(DEBUG_PARSER,
                            "Clearing literal\n"););

                            literal = 0;
                        }
                        else
                        {
                            ParseError("Replace found character value out of "
                                       "range, only hex characters allowed in binary "
                                       "content buffers");
                        }
                    }
                }

                break;

        } /* end switch */

        dummy_idx++;
        idx++;
        cnt++;
    }
    /* ...END BAD JUJU */

    /* error pruning */

    if (literal) {
        ParseError("Replace backslash escape is not completed");
    }
    if (hexmode) {
        ParseError("Replace hexmode is not completed");
    }

    if((pmd->replace_buf = (char *) calloc(dummy_size+1,
                                                  sizeof(char))) == NULL)
    {
        ParseError("Replace pattern_buf malloc failed");
            
    }

    ret = SafeMemcpy(pmd->replace_buf, tmp_buf, dummy_size,
                     pmd->replace_buf, (pmd->replace_buf+dummy_size));

    if (ret == SAFEMEM_ERROR)
    {
        ParseError("Replace SafeMemcpy failed");
    }

    pmd->replace_size = dummy_size;
    pmd->replace_depth = (int*)SnortAlloc(get_instance_max() * sizeof(int));

    DEBUG_WRAP(DebugMessage(DEBUG_PARSER,
        "pmd (%p) replace_size(%d) replace_buf(%s)\n", pmd,
        pmd->replace_size, pmd->replace_buf););
}

void PayloadReplaceInit(
    PatternMatchData* pmd, char *data, OptTreeNode * otn)
{
    static int warned = 0;

    if( !ScInlineMode() )
        return;

    if ( !DAQ_CanReplace() )
    {
        if ( !warned )
        {
            LogMessage("WARNING: payload replacements disabled because DAQ "
                " can't replace packets.\n");
            warned = 1;
        }
        return;
    }

    Replace_Parse(data, otn, pmd);
}

typedef struct {
    const char* data;
    int size;
    int depth;
} Replacement;

#define MAX_REPLACEMENTS 32
static THREAD_LOCAL Replacement rpl[MAX_REPLACEMENTS];
static THREAD_LOCAL int num_rpl = 0;

void Replace_ResetQueue(void)
{
    num_rpl = 0;
}

void Replace_QueueChange(PatternMatchData* pmd)
{
    Replacement* r;

    if ( num_rpl == MAX_REPLACEMENTS )
        return;

    r = rpl + num_rpl++;

    r->data = pmd->replace_buf;
    r->size = pmd->replace_size;
    r->depth = pmd->replace_depth[get_instance_id()];
}

static inline void Replace_ApplyChange(Packet *p, Replacement* r)
{
    uint8_t* start = (uint8_t*)p->data + r->depth;
    const uint8_t* end = p->data + p->dsize;
    unsigned len;

    if ( (start + r->size) >= end )
        len = p->dsize - r->depth;
    else
        len = r->size;

    memcpy(start, r->data, len);
}

// FIXIT this could be ContentOption::action()
// for a more general packet rewriting facility
void Replace_ModifyPacket(Packet *p)
{
    if ( num_rpl == 0 )
        return;

    for ( int n = 0; n < num_rpl; n++ )
    {
        Replace_ApplyChange(p, rpl+n);
    }
    p->packet_flags |= PKT_MODIFIED;
    num_rpl = 0;
}

