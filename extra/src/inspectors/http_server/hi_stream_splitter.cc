//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2011-2013 Sourcefire, Inc.
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

// hi_stream_splitter.c author Russ Combs <rcombs@sourcefire.com>

//--------------------------------------------------------------------
// hi stuff
//
// the goal is to perform the minimal http paf parsing required for
// correctness while maintaining loose coupling with hi proper:

// * distinguish request from response by presence of http version
//   as first token in first header of response
// * identify head request so response is understood to not have body
// * determine length of body from content-length header
// * determine chunking from transfer-endoding header
// * extract chunk lengths for body chunks
// * determine end of chunks from chunk length of zero

// 1XX, 204, or 304 status responses must not have a body per RFC but
// if other headers indicate a body is present we will process that.
// This is different for head responses because content-length or
// transfer-encoding are expected.
//
// TBD:
// * Expect: 100-continue
// * Range, Content-Range, and multipart
//--------------------------------------------------------------------

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "hi_stream_splitter.h"

#include "detection/detection_engine.h"
#include "events/event_queue.h"
#include "main/snort_debug.h"
#include "protocols/packet.h"
#include "stream/stream.h"
#include "utils/util.h"

#include "hi_events.h"

#ifdef DEBUG_MSGS
#define HI_TRACE     // define for state trace
#endif

#define HIF_REQ 0x0001  // message is request
#define HIF_RSP 0x0002  // message is response
#define HIF_LEN 0x0004  // content-length
#define HIF_CHK 0x0008  // transfer-encoding: chunked
#define HIF_NOB 0x0010  // head (no body in response)
#define HIF_NOF 0x0020  // no flush (chunked body follows)
#define HIF_V09 0x0040  // simple request version 0.9
#define HIF_V10 0x0080  // server response version 1.0
#define HIF_V11 0x0100  // server response version 1.1
#define HIF_ERR 0x0200  // flag error for deferred abort (at eoh)
#define HIF_GET 0x0400  // post (requires content-length or chunks)
#define HIF_PST 0x0800  // post (requires content-length or chunks)
#define HIF_EOL 0x1000  // already saw at least one eol (for v09)

// config stuff
static uint32_t hi_cap = 0;

// FIXIT-L eliminate these counts or make module pegs or debug only
static THREAD_LOCAL uint32_t hi_paf_calls = 0;
static THREAD_LOCAL uint32_t hi_paf_bytes = 0;

//--------------------------------------------------------------------
// char classification stuff per RFC 2616
//--------------------------------------------------------------------

#define CLASS_ERR 0x00
#define CLASS_ANY 0x01
#define CLASS_CHR 0x02
#define CLASS_TOK 0x04
#define CLASS_LWS 0x10
#define CLASS_SEP 0x20
#define CLASS_EOL 0x40
#define CLASS_DIG 0x80

static const uint8_t class_map[256] =
{
//                                                         tab    lf                cr
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x33, 0x43, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
//
//   ' ',  '!',  '"',  '#',  '$',  '%',  '&',  ''',  '(',  ')',  '*',  '+',  ',',  '-',  '.',  '/'
    0x33, 0x07, 0x23, 0x07, 0x07, 0x07, 0x07, 0x07, 0x23, 0x23, 0x07, 0x07, 0x23, 0x07, 0x07, 0x23,
//
//   '0',  '1',  '2',  '3',  '4',  '5',  '6',  '7',  '8',  '9',  ':',  ';',  '<',  '=',  '>',  '?'
    0x87, 0x87, 0x87, 0x87, 0x87, 0x87, 0x87, 0x87, 0x87, 0x87, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23,
//
//   '@',  'A',  'B',  'C',  'D',  'E',  'F',  'G',  'H',  'I',  'J',  'K',  'L',  'M',  'N',  'O'
    0x23, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
//
//   'P',  'Q',  'R',  'S',  'T',  'U',  'V',  'W',  'X',  'Y',  'Z',  '[',  '\',  ']',  '^',  '_'
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x23, 0x23, 0x23, 0x07, 0x07,
//
//   '`',  'a',  'b',  'c',  'd',  'e',  'f',  'g',  'h',  'i',  'j',  'k',  'l',  'm',  'n',  'o'
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
//
//   'p',  'q',  'r',  's',  't',  'u',  'v',  'w',  'x',  'y',  'z',  '{',  '|',  '}',  '~',  '.'
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x23, 0x07, 0x23, 0x07, 0x03,
//
//  non-ascii
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
};

// define class strings with ctl bytes to avoid collision
#define LWSS "\1"  // matches LWS (excludes \n)
#define EOLS "\2"  // matches LF (excludes \r)
#define ANYS "\3"  // matches OCTET; other not used so
                   // set other = match for consistency
#define TOKS "\4"  // matches token
#define SEPS "\5"  // matches SEP
#define CHRS "\6"  // matches CHAR
#define DIGS "\7"  // matches DIGIT

static inline bool is_lwspace(const char c)
{
    return (c == ' ' || c == '\t');
}

static uint8_t Classify(const char* s)
{
    if ( !strcmp(s, ANYS) )
        return CLASS_ANY;

    if ( !strcmp(s, CHRS) )
        return CLASS_CHR;

    if ( !strcmp(s, TOKS) )
        return CLASS_TOK;

    if ( !strcmp(s, LWSS) )
        return CLASS_LWS;

    if ( !strcmp(s, SEPS) )
        return CLASS_SEP;

    if ( !strcmp(s, EOLS) )
        return CLASS_EOL;

    if ( !strcmp(s, DIGS) )
        return CLASS_DIG;

    return CLASS_ERR;
}

//--------------------------------------------------------------------
// fsm stuff
//--------------------------------------------------------------------

typedef enum
{
    ACT_NOP, ACT_NOB,
    ACT_GET, ACT_PST,
    ACT_V09, ACT_V10, ACT_V11,
    ACT_SRL, ACT_REQ, ACT_RSP,
    ACT_SHI, ACT_SHX,
    ACT_LNB, ACT_LNC, ACT_LN0,
    ACT_CHK, ACT_CK0, ACT_HDR
} Action;

typedef struct
{
    uint8_t action;
    uint8_t next;
} Cell;

typedef struct
{
    Cell cell[256];
} State;

static State* hi_fsm = nullptr;
static unsigned hi_fsm_size = 0;

#define EOL '\n'  // \r is ignored
#define LWS ' '   // space or tab

typedef struct
{
    uint8_t state;
    uint8_t match;
    uint8_t other;
    uint8_t action;
    const char* event;
} HiRule;

// these are just convenient jump points to the start
// of blocks; the states MUST match array index
// more of these make it easier to insert states
#define P0 (0)
#define P1 (P0+6)
#define P2 (P1+10)
#define P3 (P2+3)

#define Q0 (P3+3)
#define Q1 (Q0+12)
#define Q2 (Q1+6)
#define Q3 (Q2+9)

#define R2 (Q3+3)
#define R3 (R2+5)
#define R4 (R3+5)
#define R5 (R4+1)
#define R6 (R5+4)
#define R7 (R6+2)
#define R8 (R7+2)

#define MAX_STATE        (R8+2)
#define RSP_START_STATE  (P0)
#define REQ_START_STATE  (Q0)
#define REQ_V09_STATE_1  (Q1+3)
#define REQ_V09_STATE_2  (Q2)
#define MSG_CHUNK_STATE  (R6)
#define MSG_EOL_STATE    (R8)
#define RSP_ABORT_STATE  (P3)
#define REQ_ABORT_STATE  (Q3)

// -------------------------------------------------------------------
// byte-by-byte FSM
// -- eliminates need to accumulate a copy of the current token
// -- no need to compare prefixes when branching (just current byte)
//
// however, we must split tokens at branch points to distinguish
// between non-match events at the start or later in the string.
// also must split whenever the action differs from prior.
//
// it is possible to eliminate this split but it requires a lot
// of additional complexity in the compiler.
//
// see below for other possible enhancements.
// -------------------------------------------------------------------

/* *INDENT-OFF* */
static const HiRule hi_rule[] =
{
    // P* are resPonse specific
    // http version starts response (8 chars)
    { P0+ 0, P0+ 1, P3   , ACT_SRL, "H"  },
    { P0+ 1, P0+ 2, P3+ 2, ACT_NOP, "TTP/1." },
    { P0+ 2, P0+ 4, P0+ 3, ACT_V10, "0"  },
    { P0+ 3, P0+ 4, P3   , ACT_V11, "1"  },
    { P0+ 4, P0+ 5, P3   , ACT_NOP, LWSS },
    { P0+ 5, P0+ 5, P1   , ACT_NOP, LWSS },

    // now get status code (3 chars)
    { P1+ 0, P1+ 6, P1+ 1, ACT_NOB, "1"  },
    { P1+ 1, P1+ 3, P1+ 2, ACT_NOP, "2"  },
    { P1+ 2, P1+ 3, P1+ 5, ACT_NOP, "3"  },
    { P1+ 3, P1+ 4, P1+ 6, ACT_NOP, "0"  },
    { P1+ 4, P1+ 8, P1+ 7, ACT_NOB, "4"  },
    { P1+ 5, P1+ 6, P1+ 6, ACT_NOP, DIGS },
    { P1+ 6, P1+ 7, P1+ 7, ACT_NOP, DIGS },
    { P1+ 7, P1+ 8, P3+ 2, ACT_NOP, DIGS },
    { P1+ 8, P1+ 9, P3+ 2, ACT_NOP, LWSS },
    { P1+ 9, P1+ 9, P2   , ACT_NOP, LWSS },

    // now get status message (variable)
    { P2+ 0, P2+ 1, P2+ 1, ACT_NOP, ANYS },
    { P2+ 1, R2+ 0, P2+ 2, ACT_RSP, EOLS },
    { P2+ 2, P2+ 1, P2+ 1, ACT_NOP, ANYS },

    // resync state
    { P3+ 0, P0   , P3+ 1, ACT_NOP, LWSS },
    { P3+ 1, P0   , P3+ 2, ACT_NOP, EOLS },
    { P3+ 2, P3   , P3+ 0, ACT_NOP, ANYS },

    // Q* are reQuest specific
    // get method required for 0.9 request
    { Q0+ 0, Q0+ 1, Q0+ 3, ACT_SRL, "G"  },
    { Q0+ 1, Q0+ 2, Q0+10, ACT_NOP, "ET" },
    { Q0+ 2, Q1+ 0, Q0+10, ACT_GET, LWSS },
    // head method signals no body in response
    { Q0+ 3, Q0+ 4, Q0+ 6, ACT_SRL, "H"  },
    { Q0+ 4, Q0+ 5, Q0+10, ACT_NOP, "EAD" },
    { Q0+ 5, Q1+ 0, Q0+10, ACT_NOB, LWSS },
    // post method must have content-length or chunks
    { Q0+ 6, Q0+ 7, Q0+ 9, ACT_SRL, "P"  },
    { Q0+ 7, Q0+ 8, Q0+10, ACT_NOP, "OST" },
    { Q0+ 8, Q1+ 0, Q0+10, ACT_PST, LWSS },
    // other method
    { Q0+ 9, Q0+10, Q3+ 0, ACT_SRL, TOKS },
    { Q0+10, Q0+10, Q0+11, ACT_NOP, TOKS },
    { Q0+11, Q1+ 0, Q3+ 2, ACT_NOP, LWSS },

    // this gets required URI / next token
    { Q1+ 0, R8+ 0, Q1+ 1, ACT_NOP, EOLS },
    { Q1+ 1, Q1+ 0, Q1+ 2, ACT_NOP, LWSS },
    { Q1+ 2, Q1+ 3, Q1+ 3, ACT_NOP, ANYS },
    { Q1+ 3, R8+ 0, Q1+ 4, ACT_V09, EOLS },
    { Q1+ 4, Q2+ 0, Q1+ 5, ACT_NOP, LWSS },
    { Q1+ 5, Q1+ 3, Q1+ 3, ACT_NOP, ANYS },

    // this gets version, allowing extra tokens
    // if start line doesn't end with version,
    // assume 0.9 SimpleRequest (1 line header)
    { Q2+ 0, R8+ 0, Q2+ 1, ACT_V09, EOLS },
    { Q2+ 1, Q2+ 0, Q2+ 2, ACT_NOP, LWSS },
    { Q2+ 2, Q2+ 3, Q2+ 8, ACT_NOP, "H"  },
    { Q2+ 3, Q2+ 4, Q2+ 8, ACT_NOP, "TTP/1." },
    { Q2+ 4, Q2+ 6, Q2+ 5, ACT_V10, "0"  },
    { Q2+ 5, Q2+ 6, Q2+ 8, ACT_V11, "1"  },
    { Q2+ 6, R2+ 0, Q2+ 7, ACT_REQ, EOLS },
    { Q2+ 7, Q2+ 6, Q2+ 8, ACT_NOP, LWSS },
    { Q2+ 8, Q2+ 0, Q2+ 0, ACT_NOP, ANYS },

    // resync state
    { Q3+ 0, Q0   , Q3+ 1, ACT_NOP, LWSS },
    { Q3+ 1, Q0   , Q3+ 2, ACT_NOP, EOLS },
    { Q3+ 2, Q3   , Q3+ 0, ACT_NOP, ANYS },

    // R* are request or response
    // for simplicity, we don't restrict headers to allowed
    // direction of transfer (eg cookie only from client).
    // content-length is optional
    { R2+ 0, R2+ 1, R3   , ACT_HDR, "C"  },
    { R2+ 1, R2+ 2, R8   , ACT_NOP, "ONTENT-LENGTH"  },
    { R2+ 2, R2+ 2, R2+ 3, ACT_NOP, LWSS },
    { R2+ 3, R2+ 4, R8   , ACT_NOP, ":"  },
    { R2+ 4, R2+ 4, R5   , ACT_LN0, LWSS },

    // transfer-encoding required for chunks
    { R3+ 0, R3+ 1, R8   , ACT_HDR, "T"  },
    { R3+ 1, R3+ 2, R8   , ACT_NOP, "RANSFER-ENCODING"  },
    { R3+ 2, R3+ 2, R3+ 3, ACT_NOP, LWSS },
    { R3+ 3, R3+ 4, R8   , ACT_NOP, ":"  },
    { R3+ 4, R3+ 4, R4   , ACT_NOP, LWSS },

    // only recognized encoding
    { R4+ 0, R8   , R8   , ACT_CHK, "CHUNKED" },

    // extract decimal content length
    { R5+ 0, R2   , R5+ 1, ACT_LNB, EOLS },
    { R5+ 1, R5   , R5+ 2, ACT_SHI, DIGS },
    { R5+ 2, R5   , R5+ 3, ACT_SHI, LWSS },
    { R5+ 3, R8   , R8   , ACT_SHI, ANYS },

    // extract hex chunk length
    { R6+ 0, R7   , R6+ 1, ACT_LNC, EOLS },
    { R6+ 1, R6   , R6   , ACT_SHX, ANYS },

    // skip to end of line after chunk data
    { R7+ 0, R6   , R7+ 1, ACT_LN0, EOLS },
    { R7+ 1, R7   , R7   , ACT_NOP, ANYS },

    // skip to end of line
    { R8+ 0, R2   , R8+ 1, ACT_NOP, EOLS },
    { R8+ 1, R8   , R8   , ACT_NOP, ANYS },
};
/* *INDENT-ON* */

//--------------------------------------------------------------------
// trace stuff
//--------------------------------------------------------------------

#ifdef HI_TRACE
static void get_state(int s, char* buf, int max)
{
    int nbase;
    const char* sbase;

    if ( s >= MAX_STATE )
    {
        sbase = "X"; nbase = MAX_STATE;
    }
    else if ( s >= R8 )
    {
        sbase = "R8"; nbase = R8;
    }
    else if ( s >= R7 )
    {
        sbase = "R7"; nbase = R7;
    }
    else if ( s >= R6 )
    {
        sbase = "R6"; nbase = R6;
    }
    else if ( s >= R5 )
    {
        sbase = "R5"; nbase = R5;
    }
    else if ( s >= R4 )
    {
        sbase = "R4"; nbase = R4;
    }
    else if ( s >= R3 )
    {
        sbase = "R3"; nbase = R3;
    }
    else if ( s >= R2 )
    {
        sbase = "R2"; nbase = R2;
    }
    //else if ( s >= R1 ) { sbase = "R1"; nbase = R1; }
    //else if ( s >= R0 ) { sbase = "R0"; nbase = R0; }

    else if ( s >= Q3 )
    {
        sbase = "Q3"; nbase = Q3;
    }
    else if ( s >= Q2 )
    {
        sbase = "Q2"; nbase = Q2;
    }
    else if ( s >= Q1 )
    {
        sbase = "Q1"; nbase = Q1;
    }
    else if ( s >= Q0 )
    {
        sbase = "Q0"; nbase = Q0;
    }
    else if ( s >= P3 )
    {
        sbase = "P3"; nbase = P3;
    }
    else if ( s >= P2 )
    {
        sbase = "P2"; nbase = P2;
    }
    else if ( s >= P1 )
    {
        sbase = "P1"; nbase = P1;
    }
    else
    {
        sbase = "P0"; nbase = P0;
    }

    snprintf(buf, max, "%s+%d", sbase, (s-nbase));
}

#if 0
static inline bool dump_it(int c)
{
    if ( !c )
        return false;
    return ( isupper(c) || isdigit(c) || strchr(":-/. \t\n", c) );
}

#endif

static void hi_fsm_dump()
{
#if 0
    unsigned i;
    printf("%s", "s\\e");

    for ( i = 0; i < 256; i++ )
    {
        if ( dump_it(i) )
        {
            if ( strchr(" \t\n", i) )
                printf(",%02X", i);
            else
                printf(",%c", i);
        }
    }
    printf("\n");

    for ( i = 0; i < hi_fsm_size; i++ )
    {
        unsigned c;
        char buf[16];
        get_state(i, buf, sizeof(buf));
        printf("%s", buf);

        for ( c = 0; c < 256; c++ )
        {
            if ( dump_it(c) )
            {
                get_state(hi_fsm[i].cell[c].next, buf, sizeof(buf));
                printf(",%s", buf);
            }
        }
        printf("\n");
    }
#endif
}

#endif

//--------------------------------------------------------------------
// fsm build
//--------------------------------------------------------------------

#define TBD 0xFF

static void hi_load(State* state, int event, const HiRule* rule)
{
    //assert(state->cell[event].next == TBD);

    state->cell[event].action = rule->action;
    state->cell[event].next = rule->match;
}

static void hi_reload(State* state, int event, int next)
{
    state->cell[event].action = ACT_NOP;
    state->cell[event].next = next;
}

static void hi_link(State* state, const char* event, const HiRule* rule)
{
    bool not_done;

    do
    {
        int i;
        uint8_t cls = Classify(event);
        not_done = strcmp(event, ANYS) != 0;

        if ( !cls )
        {
            hi_load(state, toupper(*event), rule);
            hi_load(state, tolower(*event), rule);
        }
        else
            for ( i = 0; i < 256; i++ )
            {
                if ( (state->cell[i].next == TBD) && (class_map[i] & cls) )
                {
                    hi_load(state, toupper(i), rule);
                    hi_load(state, tolower(i), rule);
                }
            }
        rule = hi_rule + rule->other;
        event = rule->event;
    }
    while ( not_done );
}

static void hi_relink(State* state, const char* event, int next)
{
    hi_reload(state, toupper(*event), next);
    hi_reload(state, tolower(*event), next);
}

static void hi_link_check()
{
    unsigned i, j;

    for ( i = 0; i < hi_fsm_size; i++ )
    {
        for ( j = 0; j < 256; j++ )
            assert(hi_fsm[i].cell[j].next != TBD);

        for ( j = 'A'; j <= 'Z'; j++ )
            assert(hi_fsm[i].cell[j].next == hi_fsm[i].cell[tolower(j)].next);
    }
}

static bool hi_fsm_compile()
{
    unsigned i = 0;
    unsigned max = sizeof(hi_rule) / sizeof(hi_rule[0]);
    unsigned next, extra = 0;

    while ( i < max )
    {
        // verify that HiRule.state corresponds to array index
        // HiRule.state is used solely for this sanity check.
        assert(hi_rule[i].state == i);

        if ( strlen(hi_rule[i].event) > 1 )
            extra += strlen(hi_rule[i].event) - 1;

        i++;
    }
    hi_fsm_size = max + extra;
    assert(hi_fsm_size < TBD);  // using uint8_t for Cell.next and Hi5State.fsm

    hi_fsm = (State*)snort_alloc(hi_fsm_size*sizeof(*hi_fsm));
    next = max;

    for ( i = 0; i < hi_fsm_size; i++ )
        for ( int j = 0; j < 256; j++ )
            hi_fsm[i].cell[j].next = TBD;

    for ( i = 0; i < max; i++ )
    {
        int prev = i, n = strlen(hi_rule[i].event);
        const char* event = hi_rule[i].event;

        hi_link(hi_fsm+i, event, hi_rule+i);

#if 0
        if ( n > 1 )
            printf("Expanding %s at %u\n", hi_rule[i].event, next);
#endif

        for ( int j = 1; j < n; j++ )
        {
            event = hi_rule[i].event + j;
            hi_link(hi_fsm+next, event, hi_rule+i);

            event = hi_rule[i].event + j - 1;
            hi_relink(hi_fsm+prev, event, next);

            prev = next++;
        }
    }
    hi_link_check();
    assert(max + extra == next);
    return true;
}

//--------------------------------------------------------------------
// actions
//--------------------------------------------------------------------

static inline int dton(int c)
{
    return c - '0';
}

static inline int xton(int c)
{
    if ( isdigit(c) )
        return c - '0';

    if ( isupper(c) )
        return c - 'A' + 10;

    return c - 'a' + 10;
}

static inline void hi_paf_event_post()
{
    DetectionEngine::queue_event(GID_HTTP_CLIENT, HI_CLIENT_UNBOUNDED_POST);
}

static inline void hi_paf_event_simple()
{
    DetectionEngine::queue_event(GID_HTTP_CLIENT, HI_CLIENT_SIMPLE_REQUEST);
}

static inline void hi_paf_event_msg_size()
{
    DetectionEngine::queue_event(GID_HTTP_SERVER, HI_CLISRV_MSG_SIZE_EXCEPTION);
}

static inline void hi_paf_event_pipe()
{
    DetectionEngine::queue_event(GID_HTTP_CLIENT, HI_CLIENT_PIPELINE_MAX);
}

static inline StreamSplitter::Status hi_exec(Hi5State* s, Action a, int c)
{
    switch ( a )
    {
    case ACT_HDR:
        break;
    case ACT_SRL:
        break;
    case ACT_NOP:
        break;
    case ACT_V09:
        s->flags |= HIF_REQ|HIF_V09|HIF_ERR;
        break;
    case ACT_V10:
        s->flags |= HIF_V10;
        break;
    case ACT_V11:
        s->flags |= HIF_V11;
        break;
    case ACT_NOB:
        s->flags |= HIF_NOB;
        break;
    case ACT_GET:
        s->flags |= HIF_GET;
        break;
    case ACT_PST:
        s->flags |= HIF_PST;
        break;
    case ACT_REQ:
        s->flags |= HIF_REQ;
        break;
    case ACT_RSP:
        s->flags |= HIF_RSP;
        break;
    case ACT_SHI:
        if ( s->flags & HIF_ERR )
            break;
        if ( isdigit(c) && (s->len < 429496728) )
        {
            s->len = (10 * s->len) + dton(c);
        }
        else if (!is_lwspace(c))
        {
            hi_paf_event_msg_size();
            s->flags |= HIF_ERR;
        }
        break;
    case ACT_SHX:
        if ( s->flags & HIF_ERR )
            break;
        if ( isxdigit(c) && !(s->len & 0xF8000000) )
            s->len = (s->len << 4) + xton(c);
        else
        {
            hi_paf_event_msg_size();
            s->flags |= HIF_ERR;
            return StreamSplitter::FLUSH;
        }
        break;
    case ACT_LNB:
        s->flags |= HIF_LEN;
        DebugFormat(DEBUG_STREAM_PAF, "%s: lnb=%u\n", __func__, s->len);
        break;
    case ACT_LNC:
        s->flags |= HIF_LEN;
        DebugFormat(DEBUG_STREAM_PAF, "%s: lnc=%u\n", __func__, s->len);
        if ( s->len )
            return StreamSplitter::SKIP;
        s->flags &= ~HIF_NOF;
        s->msg = 3;
        break;
    case ACT_LN0:
        s->len = 0;
        break;
    case ACT_CHK:
        s->flags |= HIF_CHK;
        break;
    case ACT_CK0:
        s->flags |= HIF_NOF;
        s->flags &= ~HIF_CHK;
        s->fsm = MSG_CHUNK_STATE;
        s->len = 0;
        break;
    }
    return StreamSplitter::SEARCH;
}

//--------------------------------------------------------------------

static inline Hi5State* get_state(Flow* flow, bool c2s)
{
    if ( !flow )
        return nullptr;

    HttpSplitter* s = (HttpSplitter*)Stream::get_splitter(flow, c2s);
    return s ? &s->state : nullptr;
}

bool hi_paf_simple_request(Flow* ssn)
{
    Hi5State* ps = get_state(ssn, true);
    return ( ps && (ps->flags & HIF_V09) );
}

//--------------------------------------------------------------------
// pipeline
//--------------------------------------------------------------------

#define MAX_PIPELINE       24
#define PIPELINE_RUPTURED 255

static void hi_pipe_push(Hi5State* s_req, Flow* ssn)
{
    uint32_t nreq = s_req->pipe & 0xFF;
    uint32_t pipe = s_req->pipe >> 8;

    DebugFormat(DEBUG_STREAM_PAF, "%s: nreq=%u, pipe=0x%X\n", __func__, nreq, pipe);

    if ( nreq == MAX_PIPELINE )
    {
        if ( Stream::is_paf_active(ssn, 0) )
            hi_paf_event_pipe();
    }
    else if ( nreq < MAX_PIPELINE )
    {
        if ( s_req->flags & HIF_NOB )
            pipe |= (0x1 << nreq);
    }
    if ( nreq == PIPELINE_RUPTURED )
        return;

    s_req->pipe = (pipe << 8) | ++nreq;
}

static void hi_pipe_pop(Hi5State* s_rsp, Flow* ssn)
{
    Hi5State* s_req = get_state(ssn, true);

    if ( !s_req )
        return;

    uint32_t nreq = s_req->pipe & 0xFF;
    uint32_t pipe = s_req->pipe >> 8;

    DebugFormat(DEBUG_STREAM_PAF, "%s: nreq=%u, pipe=0x%X\n", __func__, nreq, pipe);

    // FIXIT-L valgrind: Conditional jump or move depends on uninitialised value(s)
    if ( nreq == 0 || nreq == PIPELINE_RUPTURED )
        return;

    // FIXIT-L valgrind: Conditional jump or move depends on uninitialised value(s)
    if ( --nreq < MAX_PIPELINE )
    {
        if ( pipe & 0x1 )
            s_rsp->flags |= HIF_NOB;
    }
    pipe >>= 1;
    s_req->pipe = (pipe << 8) | nreq;
}

//--------------------------------------------------------------------
// control
//--------------------------------------------------------------------

static inline bool simple_allowed(Hi5State* s)
{
    return ( (s->fsm == REQ_V09_STATE_1 || s->fsm == REQ_V09_STATE_2)
           && s->flags & HIF_GET );
}

static inline bool have_pdu(Hi5State* s)
{
    return ( s->fsm != REQ_START_STATE && s->fsm != RSP_START_STATE );
}

static inline bool paf_abort(Hi5State* s)
{
    return ( s->fsm == REQ_ABORT_STATE || s->fsm == RSP_ABORT_STATE );
}

// this is the 2nd step of stateful scanning, which executes
// the fsm.
static StreamSplitter::Status hi_scan_fsm(Hi5State* s, int c)
{
    StreamSplitter::Status status;
    State* m = hi_fsm + s->fsm;
    Cell* cell = &m->cell[c];

#ifdef HI_TRACE
    char before[16], after[16];
    uint8_t prev = s->fsm;
#endif

    s->fsm = cell->next;

#ifdef HI_TRACE
    get_state(prev, before, sizeof(before));
    get_state(s->fsm, after, sizeof(after));
    DebugFormat(DEBUG_STREAM_PAF,
        "%s: %s(%hhu)[0x%2X, '%c'] -> %d,%s(%hhu)\n",
        __func__, before, prev, c, isgraph(c) ? c : '.',
        cell->action, after, s->fsm);
#endif

    status = hi_exec(s, (Action)cell->action, c);

    return status;
}

static StreamSplitter::Status hi_eoh(Hi5State* s, Flow* ssn)
{
    DebugFormat(DEBUG_STREAM_PAF, "%s: flags=0x%X, len=%u\n", __func__, s->flags, s->len);

    if ( (s->flags & HIF_REQ) )
        hi_pipe_push(s, ssn);
    else
        hi_pipe_pop(s, ssn);

    if ( (s->flags & HIF_PST) &&
        !(s->flags & (HIF_CHK|HIF_LEN)) )
    {
        hi_paf_event_post();
        s->flags |= HIF_ERR;
    }
    if ( (s->flags & HIF_ERR) ||
        ((s->flags & HIF_NOB) && (s->flags & HIF_RSP))
        )
    {
        if ( s->flags & HIF_V09 )
            hi_paf_event_simple();

        hi_exec(s, ACT_LN0, 0);
        return StreamSplitter::FLUSH;
    }
    if ( s->flags & HIF_CHK )
    {
        hi_exec(s, ACT_CK0, 0);
        return StreamSplitter::SEARCH;
    }
    if ( (s->flags & (HIF_REQ|HIF_LEN)) )
        return StreamSplitter::FLUSH;

    if ( (s->flags & HIF_V11) && (s->flags & HIF_RSP) )
    {
        hi_exec(s, ACT_LN0, 0);
        hi_paf_event_msg_size();
        return StreamSplitter::FLUSH;
    }
    return StreamSplitter::ABORT;
}

// http messages are scanned statefully, char-by-char, in
// two steps.  this is the 1st step, which figures out
// end-of-line (eol) and end-of-headers (eoh) from the byte
// stream.  also unfolds headers before fsm scanning.  this
// simplified version ignores \r (in the spirit of send strict,
// recv tolerant, but it would only take 2 more states to check
// for \r).  the 2nd step is hi_scan_fsm().
static inline StreamSplitter::Status hi_scan_msg(
    Hi5State* s, int c, uint32_t* fp, Flow* ssn)
{
    StreamSplitter::Status paf = StreamSplitter::SEARCH;
    DebugFormat(DEBUG_STREAM_PAF,
        "%s[%d]: 0x%2X, '%c'\n", __func__, s->msg, c, isgraph(c) ? c : '.');

    if ( c == '\r' )
    {
        *fp = 0;
        return paf;
    }
    switch ( s->msg )
    {
    case 0:
        if ( c == '\n' )
        {
            if ( !(s->flags & HIF_EOL) )
            {
                s->flags |= HIF_EOL;

                if ( simple_allowed(s) )
                {
                    hi_scan_fsm(s, EOL);
                    paf = hi_eoh(s, ssn);
                }
                else
                    s->msg = 1;
            }
            else if ( s->flags & HIF_NOF )
                paf = hi_scan_fsm(s, EOL);
            else
                s->msg = 1;
        }
        else
            paf = hi_scan_fsm(s, c);
        break;

    case 1:
        if ( c == '\n' )
        {
            hi_scan_fsm(s, EOL);

            if ( have_pdu(s) )
                paf = hi_eoh(s, ssn);
        }
        else if ( c == ' ' || c == '\t' )
        {
            // folding, just continue
            paf = hi_scan_fsm(s, LWS);
        }
        else
        {
            paf = hi_scan_fsm(s, EOL);

            if ( paf == StreamSplitter::SEARCH )
                paf = hi_scan_fsm(s, c);
        }
        s->msg = 0;
        break;

    case 3:
        if ( c == '\n' )
            paf = hi_eoh(s, ssn);
        else
            s->msg = 4;
        break;

    case 4:
        if ( c == '\n' )
            s->msg = 3;
        break;
    }

    if ( paf_abort(s) )
        paf = StreamSplitter::ABORT;

    else if ( paf != StreamSplitter::SEARCH )
        *fp = s->len;

    return paf;
}

//--------------------------------------------------------------------
// utility
//--------------------------------------------------------------------

static void hi_reset(Hi5State* s, uint32_t flags)
{
    s->len = s->msg = 0;

    if ( flags & PKT_FROM_CLIENT )
    {
        s->fsm = REQ_START_STATE;
    }
    else
    {
        s->fsm = RSP_START_STATE;
    }
    s->flags = 0;

    DebugFormat(DEBUG_STREAM_PAF, "%s: fsm=%hhu, flags=0x%X\n", __func__, s->fsm, s->flags);
}

//--------------------------------------------------------------------
// callback for stateful scanning of in-order raw payload
//--------------------------------------------------------------------

HttpSplitter::HttpSplitter(bool c2s) : StreamSplitter(c2s)
{
    memset(&state, 0, sizeof(state));

    if ( c2s )
        state.fsm = REQ_START_STATE;
    else
        state.fsm = RSP_START_STATE;
}

HttpSplitter::~HttpSplitter() { }

StreamSplitter::Status HttpSplitter::scan(
    Flow* ssn, const uint8_t* data, uint32_t len,
    uint32_t flags, uint32_t* fp)
{
    Hi5State* hip = &state;
    Status paf = SEARCH;

    uint32_t n = 0;
    *fp = 0;

    DebugFormat(DEBUG_STREAM_PAF, "%s: len=%u\n", __func__, len);

    if ( hip->flags & HIF_ERR )
    {
        return ABORT;
    }

    if ( hi_cap && (hi_paf_bytes > hi_cap) )
    {
        return ABORT;
    }

    while ( n < len )
    {
        // jump ahead to next linefeed when possible
        if ( (hip->msg == 0) && (hip->fsm == MSG_EOL_STATE) )
        {
            uint8_t* lf = (uint8_t*)memchr(data+n, '\n', len-n);
            if ( !lf )
            {
                n = len;
                break;
            }
            n += (lf - (data + n));
        }
        paf = hi_scan_msg(hip, data[n++], fp, ssn);

        if ( paf != SEARCH )
        {
            if ( hip->flags & HIF_ERR )
            {
                *fp = len;
                break;
            }
            *fp += n;

            if ( paf != SKIP )
                hi_reset(hip, flags);
            break;
        }
    }
    DebugFormat(DEBUG_STREAM_PAF, "%s: paf=%d, rfp=%u\n", __func__, paf, *fp);

    hi_paf_calls++;
    hi_paf_bytes += n;

    return paf;
}

//--------------------------------------------------------------------
// public stuff
//--------------------------------------------------------------------

bool hi_paf_init(uint32_t cap)
{
    DebugFormat(DEBUG_STREAM_PAF, "%s: cap=%u\n",  __func__, cap);

    hi_cap = cap;

    if ( !hi_fsm_compile() )
        return false;

#ifdef HI_TRACE
    hi_fsm_dump();
#endif

    return true;
}

void hi_paf_term()
{
    snort_free(hi_fsm);
    DebugFormat(DEBUG_STREAM_PAF,
        "%s: calls=%u, bytes=%u\n",  __func__, hi_paf_calls, hi_paf_bytes);

    hi_fsm = NULL;
    hi_fsm_size = 0;
}

