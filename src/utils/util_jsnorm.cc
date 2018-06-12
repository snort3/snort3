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
// Writen by Bhagyashree Bantwal <bbantwal@sourcefire.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "util_jsnorm.h"

#include <cstdlib>
#include <cstring>

#include "main/thread.h"

namespace snort
{
#define INVALID_HEX_VAL (-1)
#define MAX_BUF 8
#define NON_ASCII_CHAR 0xff

//Return values
#define RET_OK         0
#define RET_QUIT      (-1)
#define RET_INV       (-2)

#define IS_OCT      0x1
#define IS_DEC      0X2
#define IS_HEX      0x4
#define IS_PERCENT  0x8
#define IS_UPERCENT 0x10
#define IS_BACKSLASH 0x20
#define IS_UBACKSLASH 0x40

#define ANY '\0'

enum ActionPNorm
{
    PNORM_ACT_DQUOTES,
    PNORM_ACT_NOP,
    PNORM_ACT_PLUS,
    PNORM_ACT_SPACE,
    PNORM_ACT_SQUOTES,
    PNORM_ACT_WITHIN_QUOTES
};

// Actions for SFCC
enum ActionSFCC
{
    SFCC_ACT_COMMA,
    SFCC_ACT_DEC,
    SFCC_ACT_HEX,
    SFCC_ACT_INV,
    SFCC_ACT_NOP,
    SFCC_ACT_OCT,
    SFCC_ACT_QUIT,
    SFCC_ACT_SPACE
};

// Actions for Unescape
enum ActionUnsc
{
    UNESC_ACT_BACKSLASH,
    UNESC_ACT_CONV,
    UNESC_ACT_NOP,
    UNESC_ACT_PAREN,
    UNESC_ACT_PERCENT,
    UNESC_ACT_QUIT,
    UNESC_ACT_SAVE,
    UNESC_ACT_SAVE_NOP,
    UNESC_ACT_SPACE,
    UNESC_ACT_UBACKSLASH,
    UNESC_ACT_UPERCENT,
    UNESC_ACT_UNESCAPE
};

// Actions for Javascript norm
enum ActionJSNorm
{
    ACT_NOP,
    ACT_QUIT,
    ACT_SAVE,
    ACT_SFCC,
    ACT_SPACE,
    ACT_UNESCAPE
};

static const int hex_lookup[256] =
{
    INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL,
    INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL,
    INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL,
    INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL,

    INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL,
    INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL,
    0,               1,               2,               3,               4,               5,               6,               7,
    8,               9,               INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL,

    INVALID_HEX_VAL, 10,              11,              12,              13,              14,              15,              INVALID_HEX_VAL,
    INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL,
    INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL,
    INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL,

    INVALID_HEX_VAL, 10,              11,              12,              13,              14,              15,              INVALID_HEX_VAL,
    INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL,
    INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL,
    INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL,

    INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL,
    INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL,
    INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL,
    INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL,

    INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL,
    INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL,
    INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL,
    INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL,

    INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL,
    INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL,
    INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL,
    INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL,

    INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL,
    INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL,
    INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL,
    INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL, INVALID_HEX_VAL,
};

static const int valid_chars[256] =
{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    IS_OCT|IS_DEC|IS_HEX, IS_OCT|IS_DEC|IS_HEX, IS_OCT|IS_DEC|IS_HEX, IS_OCT|IS_DEC|IS_HEX,
        IS_OCT|IS_DEC|IS_HEX, IS_OCT|IS_DEC|IS_HEX, IS_OCT|IS_DEC|IS_HEX, IS_OCT|IS_DEC|IS_HEX,
        IS_DEC|IS_HEX, IS_DEC|IS_HEX, 0, 0, 0, 0, 0, 0,

    0, IS_HEX, IS_HEX, IS_HEX, IS_HEX, IS_HEX, IS_HEX, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, IS_HEX, IS_HEX, IS_HEX, IS_HEX, IS_HEX, IS_HEX, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,

    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,

    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

struct JSNorm
{
    uint8_t state;
    uint8_t event;
    uint8_t match;
    uint8_t other;
    uint8_t action;
};

struct Dbuf
{
    char* data;
    uint16_t size;
    uint16_t len;
};

struct PNormState
{
    uint8_t fsm;
    uint8_t fsm_other;
    uint8_t prev_event;
    uint8_t d_quotes;
    uint8_t s_quotes;
    uint16_t num_spaces;
    char* overwrite;
    Dbuf output;
};

struct SFCCState
{
    uint8_t fsm;
    uint8_t buf[MAX_BUF];
    uint8_t buflen;
    uint16_t cur_flags;
    uint16_t alert_flags;
    Dbuf output;
};

struct JSNormState
{
    uint8_t fsm;
    uint8_t prev_event;
    uint16_t num_spaces;
    uint8_t* unicode_map;
    char* overwrite;
    Dbuf dest;
};

struct UnescapeState
{
    uint8_t fsm;
    uint8_t multiple_levels;
    uint8_t prev_event;
    uint16_t alert_flags;
    uint16_t num_spaces;
    int iNorm;
    int paren_count;
    uint8_t* unicode_map;
    char* overwrite;
    ActionUnsc prev_action;
    Dbuf output;
};

// STATES for SFCC
#define S0  0
#define S1 (S0+3)
#define S2 (S1+1)
#define S3 (S2+1)
#define S4 (S3+1)

static const JSNorm sfcc_norm[] =
{
    { S0+0, '(', S0+1, S0+1, SFCC_ACT_NOP },
    { S0+1, '0', S0+2, S1+0, SFCC_ACT_NOP },
    { S0+2, 'X', S3+0, S2+0, SFCC_ACT_NOP },

    //decimal
    { S1+0, IS_DEC, S1+0, S4+0, SFCC_ACT_DEC },

    //Octal
    { S2+0, IS_OCT, S2+0, S1+0, SFCC_ACT_OCT },

    //Hex
    { S3+0, IS_HEX, S3+0, S4+0, SFCC_ACT_HEX },

    { S4+0, ',', S0+1, S4+1, SFCC_ACT_COMMA },
    { S4+1, ')', S0+1, S4+2, SFCC_ACT_QUIT },
    { S4+2, ANY, S4+1, S0+1, SFCC_ACT_INV }
};

#define U0 0
#define U1 (U0+1)
#define U2 (U1+8)
#define U3 (U2+9)
#define U4 (U3+8)
#define U5 (U4+19)
#define U6 (U5+18)
#define U7 (U6+1)

static const JSNorm unescape_norm[] =
{
    { U0+ 0, '(', U1+ 0, U1+ 0, UNESC_ACT_PAREN },

    { U1+ 0, '%', U1+ 1, U2+ 0, UNESC_ACT_SAVE },
    { U1+ 1, IS_HEX, U1+ 2, U1+ 3, UNESC_ACT_CONV },
    { U1+ 2, IS_HEX, U0+ 0, U0+ 0, UNESC_ACT_PERCENT },
    { U1+ 3, 'U', U1+ 4, U0+ 0, UNESC_ACT_SAVE_NOP },
    { U1+ 4, IS_HEX, U1+ 5, U0+ 0, UNESC_ACT_CONV },
    { U1+ 5, IS_HEX, U1+ 6, U0+ 0, UNESC_ACT_CONV },
    { U1+ 6, IS_HEX, U1+ 7, U0+ 0, UNESC_ACT_CONV },
    { U1+ 7, IS_HEX, U0+ 0, U0+ 0, UNESC_ACT_UPERCENT },

    { U2+ 0, '\\', U2+ 1, U3+ 0, UNESC_ACT_SAVE },
    { U2+ 1, 'X', U2+ 2, U2+ 4, UNESC_ACT_SAVE_NOP },
    { U2+ 2, IS_HEX, U2+ 3, U0+ 0, UNESC_ACT_CONV },
    { U2+ 3, IS_HEX, U0+ 0, U0+ 0, UNESC_ACT_BACKSLASH },
    { U2+ 4, 'U', U2+ 5, U0+ 0, UNESC_ACT_CONV },
    { U2+ 5, IS_HEX, U2+ 6, U0+ 0, UNESC_ACT_CONV },
    { U2+ 6, IS_HEX, U2+ 7, U0+ 0, UNESC_ACT_CONV },
    { U2+ 7, IS_HEX, U2+ 8, U0+ 0, UNESC_ACT_CONV },
    { U2+ 8, IS_HEX, U0+ 0, U0+ 0, UNESC_ACT_UBACKSLASH },

    { U3+ 0, 'U', U3+ 1, U4+ 0, UNESC_ACT_NOP },
    { U3+ 1, 'N', U3+ 2, U0+ 0, UNESC_ACT_NOP },
    { U3+ 2, 'E', U3+ 3, U0+ 0, UNESC_ACT_NOP },
    { U3+ 3, 'S', U3+ 4, U0+ 0, UNESC_ACT_NOP },
    { U3+ 4, 'C', U3+ 5, U0+ 0, UNESC_ACT_NOP },
    { U3+ 5, 'A', U3+ 6, U0+ 0, UNESC_ACT_NOP },
    { U3+ 6, 'P', U3+ 7, U0+ 0, UNESC_ACT_NOP },
    { U3+ 7, 'E', U0+ 0, U0+ 0, UNESC_ACT_UNESCAPE },

    { U4+ 0, 'S', U4+ 1, U5+ 0, UNESC_ACT_NOP },
    { U4+ 1, 'T', U4+ 2, U0+ 0, UNESC_ACT_NOP },
    { U4+ 2, 'R', U4+ 3, U0+ 0, UNESC_ACT_NOP },
    { U4+ 3, 'I', U4+ 4, U0+ 0, UNESC_ACT_NOP },
    { U4+ 4, 'N', U4+ 5, U0+ 0, UNESC_ACT_NOP },
    { U4+ 5, 'G', U4+ 6, U0+ 0, UNESC_ACT_NOP },
    { U4+ 6, '.', U4+ 7, U0+ 0, UNESC_ACT_NOP },
    { U4+ 7, 'F', U4+ 8, U0+ 0, UNESC_ACT_NOP },
    { U4+ 8, 'R', U4+ 9, U0+ 0, UNESC_ACT_NOP },
    { U4+ 9, 'O', U4+10, U0+ 0, UNESC_ACT_NOP },
    { U4+10, 'M', U4+11, U0+ 0, UNESC_ACT_NOP },
    { U4+11, 'C', U4+12, U0+ 0, UNESC_ACT_NOP },
    { U4+12, 'H', U4+13, U0+ 0, UNESC_ACT_NOP },
    { U4+13, 'A', U4+14, U0+ 0, UNESC_ACT_NOP },
    { U4+14, 'R', U4+15, U0+ 0, UNESC_ACT_NOP },
    { U4+15, 'C', U4+16, U0+ 0, UNESC_ACT_NOP },
    { U4+16, 'O', U4+17, U0+ 0, UNESC_ACT_NOP },
    { U4+17, 'D', U4+18, U0+ 0, UNESC_ACT_NOP },
    { U4+18, 'E', U0+ 0, U0+ 0, UNESC_ACT_UNESCAPE },

    { U5+ 0, 'D', U5+ 1, U6+ 0, UNESC_ACT_NOP },
    { U5+ 1, 'E', U5+ 2, U0+ 0, UNESC_ACT_NOP },
    { U5+ 2, 'C', U5+ 3, U0+ 0, UNESC_ACT_NOP },
    { U5+ 3, 'O', U5+ 4, U0+ 0, UNESC_ACT_NOP },
    { U5+ 4, 'D', U5+ 5, U0+ 0, UNESC_ACT_NOP },
    { U5+ 5, 'E', U5+ 6, U0+ 0, UNESC_ACT_NOP },
    { U5+ 6, 'U', U5+ 7, U0+ 0, UNESC_ACT_NOP },
    { U5+ 7, 'R', U5+ 8, U0+ 0, UNESC_ACT_NOP },
    { U5+ 8, 'I', U5+ 9, U0+ 0, UNESC_ACT_UNESCAPE },
    { U5+ 9, 'C', U5+10, U0+ 0, UNESC_ACT_NOP },
    { U5+10, 'O', U5+11, U0+ 0, UNESC_ACT_NOP },
    { U5+11, 'M', U5+12, U0+ 0, UNESC_ACT_NOP },
    { U5+12, 'P', U5+13, U0+ 0, UNESC_ACT_NOP },
    { U5+13, 'O', U5+14, U0+ 0, UNESC_ACT_NOP },
    { U5+14, 'N', U5+15, U0+ 0, UNESC_ACT_NOP },
    { U5+15, 'E', U5+16, U0+ 0, UNESC_ACT_NOP },
    { U5+16, 'N', U5+17, U0+ 0, UNESC_ACT_NOP },
    { U5+17, 'T', U0+ 0, U0+ 0, UNESC_ACT_UNESCAPE },

    { U6+ 0, ')', U0+ 0, U7+ 0, UNESC_ACT_QUIT },

    { U7+ 0, ANY, U0+ 0, U0+ 0, UNESC_ACT_NOP }
};

#define P0 0
#define P1 (P0+3)
#define P2 (P1+2)
#define P3 (P2+2)
#define P4 (P3+1)

static const JSNorm plus_norm[]=
{
    { P0+ 0, ' ', P0+ 0, P0+ 1, PNORM_ACT_SPACE },
    { P0+ 1, '"', P1+ 0, P0+ 2, PNORM_ACT_DQUOTES },
    { P0+ 2, '\'', P2+ 0, P3+ 0, PNORM_ACT_SQUOTES },

    { P1+ 0, '"', P0+ 0, P1+ 1, PNORM_ACT_DQUOTES },
    { P1+ 1, ANY, P1+ 0, P1+ 0, PNORM_ACT_WITHIN_QUOTES },

    { P2+ 0, '\'', P0+ 0, P2+ 1, PNORM_ACT_SQUOTES },
    { P2+ 1, ANY, P2+ 0, P2+ 0, PNORM_ACT_WITHIN_QUOTES },

    { P3+ 0, '+', P0+ 0, P4+ 0, PNORM_ACT_PLUS },

    { P4+ 0, ANY, P0+ 0, P0+ 0, PNORM_ACT_NOP }
};

#define Z0 0
#define Z1 (Z0+9)
#define Z2 (Z1+20)
#define Z3 (Z2+19)
#define Z6 (Z3+10)

static const JSNorm javascript_norm[] =
{
    { Z0+ 0, 'U', Z0+ 1, Z1+ 0, ACT_SAVE },
    { Z0+ 1, 'N', Z0+ 2, Z0+ 0, ACT_NOP },
    { Z0+ 2, 'E', Z0+ 3, Z0+ 0, ACT_NOP },
    { Z0+ 3, 'S', Z0+ 4, Z0+ 0, ACT_NOP },
    { Z0+ 4, 'C', Z0+ 5, Z0+ 0, ACT_NOP },
    { Z0+ 5, 'A', Z0+ 6, Z0+ 0, ACT_NOP },
    { Z0+ 6, 'P', Z0+ 7, Z0+ 0, ACT_NOP },
    { Z0+ 7, 'E', Z0+ 8, Z0+ 0, ACT_NOP },
    { Z0+ 8, '(', Z0+ 0, Z0+ 0, ACT_UNESCAPE },

    { Z1+ 0, 'S', Z1+ 1, Z2+ 0, ACT_SAVE },
    { Z1+ 1, 'T', Z1+ 2, Z0+ 0, ACT_NOP },
    { Z1+ 2, 'R', Z1+ 3, Z0+ 0, ACT_NOP },
    { Z1+ 3, 'I', Z1+ 4, Z0+ 0, ACT_NOP },
    { Z1+ 4, 'N', Z1+ 5, Z0+ 0, ACT_NOP },
    { Z1+ 5, 'G', Z1+ 6, Z0+ 0, ACT_NOP },
    { Z1+ 6, '.', Z1+ 7, Z0+ 0, ACT_NOP },
    { Z1+ 7, 'F', Z1+ 8, Z0+ 0, ACT_NOP },
    { Z1+ 8, 'R', Z1+ 9, Z0+ 0, ACT_NOP },
    { Z1+ 9, 'O', Z1+10, Z0+ 0, ACT_NOP },
    { Z1+10, 'M', Z1+11, Z0+ 0, ACT_NOP },
    { Z1+11, 'C', Z1+12, Z0+ 0, ACT_NOP },
    { Z1+12, 'H', Z1+13, Z0+ 0, ACT_NOP },
    { Z1+13, 'A', Z1+14, Z0+ 0, ACT_NOP },
    { Z1+14, 'R', Z1+15, Z0+ 0, ACT_NOP },
    { Z1+15, 'C', Z1+16, Z0+ 0, ACT_NOP },
    { Z1+16, 'O', Z1+17, Z0+ 0, ACT_NOP },
    { Z1+17, 'D', Z1+18, Z0+ 0, ACT_NOP },
    { Z1+18, 'E', Z1+19, Z0+ 0, ACT_NOP },
    { Z1+19, '(', Z0+ 0, Z0+ 0, ACT_SFCC },

    { Z2+ 0, 'D', Z2+ 1, Z3+ 0, ACT_SAVE },
    { Z2+ 1, 'E', Z2+ 2, Z0+ 0, ACT_NOP },
    { Z2+ 2, 'C', Z2+ 3, Z0+ 0, ACT_NOP },
    { Z2+ 3, 'O', Z2+ 4, Z0+ 0, ACT_NOP },
    { Z2+ 4, 'D', Z2+ 5, Z0+ 0, ACT_NOP },
    { Z2+ 5, 'E', Z2+ 6, Z0+ 0, ACT_NOP },
    { Z2+ 6, 'U', Z2+ 7, Z0+ 0, ACT_NOP },
    { Z2+ 7, 'R', Z2+ 8, Z0+ 0, ACT_NOP },
    { Z2+ 8, 'I', Z2+ 9, Z0+ 0, ACT_NOP },
    { Z2+ 9, 'C', Z2+10, Z2+18, ACT_NOP },
    { Z2+10, 'O', Z2+11, Z0+ 0, ACT_NOP },
    { Z2+11, 'M', Z2+12, Z0+ 0, ACT_NOP },
    { Z2+12, 'P', Z2+13, Z0+ 0, ACT_NOP },
    { Z2+13, 'O', Z2+14, Z0+ 0, ACT_NOP },
    { Z2+14, 'N', Z2+15, Z0+ 0, ACT_NOP },
    { Z2+15, 'E', Z2+16, Z0+ 0, ACT_NOP },
    { Z2+16, 'N', Z2+17, Z0+ 0, ACT_NOP },
    { Z2+17, 'T', Z2+18, Z0+ 0, ACT_NOP },
    { Z2+18, '(', Z0+ 0, Z0+ 0, ACT_UNESCAPE },

    { Z3+ 0, '<', Z3+ 1, Z6+ 0, ACT_NOP },
    { Z3+ 1, '/', Z3+ 2, Z0+ 0, ACT_NOP },
    { Z3+ 2, 'S', Z3+ 3, Z0+ 0, ACT_NOP },
    { Z3+ 3, 'C', Z3+ 4, Z0+ 0, ACT_NOP },
    { Z3+ 4, 'R', Z3+ 5, Z0+ 0, ACT_NOP },
    { Z3+ 5, 'I', Z3+ 6, Z0+ 0, ACT_NOP },
    { Z3+ 6, 'P', Z3+ 7, Z0+ 0, ACT_NOP },
    { Z3+ 7, 'T', Z3+ 8, Z0+ 0, ACT_NOP },
    { Z3+ 8, '>', Z3+ 0, Z3+ 9, ACT_QUIT },
    { Z3+ 9, ANY, Z3+ 8, Z3+ 8, ACT_NOP },

    { Z6+ 0, ANY, Z0+ 0, Z0+ 0, ACT_NOP }
};

static void UnescapeDecode(const char* src, uint16_t srclen, const char** ptr, char** dst, size_t dst_len,
    uint16_t* bytes_copied, JSState* js, uint8_t* iis_unicode_map);

static inline int outBounds(const char* start, const char* end, const char* ptr)
{
    if ((ptr >= start) && (ptr < end))
        return 0;
    else
        return -1;
}

static inline void CheckWSExceeded(JSState* js, uint16_t* num_spaces)
{
    if (js->allowed_spaces && (*num_spaces > js->allowed_spaces))
    {
        js->alerts |= ALERT_SPACES_EXCEEDED;
    }

    *num_spaces = 0;
}

static void WriteDecodedPNorm(PNormState* s, int c, JSState* js)
{
    const char* dstart, * dend;
    char* dptr;

    dstart = s->output.data;
    dend = s->output.data + s->output.size;
    dptr = s->output.data + s->output.len;

    CheckWSExceeded(js, &(s->num_spaces));

    if (dptr < dend)
    {
        *dptr = (char)c;
        dptr++;
    }

    s->output.len = dptr - dstart;
}

static int PNorm_exec(PNormState* s, ActionPNorm a, int c, JSState* js)
{
    char* cur_ptr;
    int iRet = RET_OK;

    cur_ptr = s->output.data+ s->output.len;

    switch (a)
    {
    case PNORM_ACT_DQUOTES:
        if (s->prev_event == '\\')
        {
            s->fsm = s->fsm_other;
            WriteDecodedPNorm(s, c, js);
            break;
        }
        s->d_quotes++;
        if ( s->d_quotes == 2)
        {
            s->overwrite = cur_ptr;
            WriteDecodedPNorm(s, c, js);
            s->d_quotes = 0;
            break;
        }
        if (s->prev_event == '+')
        {
            s->prev_event = 0;
            if ( s->overwrite && (s->overwrite < cur_ptr))
            {
                s->output.len = s->overwrite - s->output.data;
            }
            else
            {
                WriteDecodedPNorm(s, c, js);
            }
        }
        else
        {
            WriteDecodedPNorm(s, c, js);
        }
        break;
    case PNORM_ACT_NOP:
        s->prev_event = c;
        s->overwrite = nullptr;
        WriteDecodedPNorm(s, c, js);
        break;
    case PNORM_ACT_PLUS:
        s->prev_event = '+';
        WriteDecodedPNorm(s, c, js);
        break;
    case PNORM_ACT_SPACE:
        if ( s->num_spaces == 0)
        {
            WriteDecodedPNorm(s, c, js);
        }
        s->num_spaces++;
        break;
    case PNORM_ACT_SQUOTES:
        if (s->prev_event == '\\')
        {
            s->fsm = s->fsm_other;
            WriteDecodedPNorm(s, c, js);
            break;
        }
        s->s_quotes++;
        if ( s->s_quotes == 2)
        {
            s->overwrite = cur_ptr;
            WriteDecodedPNorm(s, c, js);
            s->s_quotes = 0;
            break;
        }
        if (s->prev_event == '+')
        {
            s->prev_event = 0;
            if ( s->overwrite && (s->overwrite < cur_ptr))
            {
                s->output.len = s->overwrite - s->output.data;
            }
            else
            {
                WriteDecodedPNorm(s, c, js);
            }
        }
        else
        {
            WriteDecodedPNorm(s, c, js);
        }
        break;
    case PNORM_ACT_WITHIN_QUOTES:
        s->prev_event = c;
        WriteDecodedPNorm(s, c, js);
    default:
        break;
    }

    return iRet;
}

static int PNorm_scan_fsm(PNormState* s, int c, JSState* js)
{
    char uc;
    const JSNorm* m = plus_norm + s->fsm;

    uc = toupper(c);

    if (isspace(c))
    {
        c = uc =' ';
    }

    do
    {
        if ( !m->event ||  ( m->event == uc))
        {
            s->fsm = m->match;
            s->fsm_other = m->other;
            break;
        }

        s->fsm = m->other;
        m = plus_norm + s->fsm;
    }
    while ( true );

    return(PNorm_exec(s, (ActionPNorm)m->action, c, js));
}

static int PNormDecode(char* src, uint16_t srclen, char* dst, uint16_t dstlen, uint16_t* bytes_copied,
    JSState* js)
{
    int iRet = RET_OK;
    const char* end;
    char* ptr;
    PNormState s;

    end = src + srclen;
    ptr = src;

    s.fsm = 0;
    s.prev_event = 0;
    s.d_quotes = 0;
    s.s_quotes = 0;
    s.output.data = dst;
    s.output.size = dstlen;
    s.output.len = 0;
    s.overwrite = nullptr;
    s.num_spaces = 0;
    s.fsm_other = 0;

    while (ptr < end)
    {
        iRet = PNorm_scan_fsm(&s, *ptr, js);
        ptr++;
    }

    //dst = s.output.data;  FIXIT-L dead store; should be?
    *bytes_copied = s.output.len;

    return iRet;
}

static int ConvertToChar(uint16_t flags, uint8_t* buf, uint8_t buflen)
{
    int val = 0;
    char* p = nullptr;
    buf[buflen] = ANY;

    if (flags & IS_DEC)
    {
        val = strtoul( (const char*)buf, &p, 10);
    }
    else if (flags & IS_OCT)
    {
        val = strtoul( (const char*)buf, &p, 8);
    }
    else if (flags & IS_HEX)
    {
        val = strtoul( (const char*)buf, &p, 16);
    }

    return val;
}

static void WriteDecodedSFCC(SFCCState* s)
{
    char* start = s->output.data;
    char* end = s->output.data + s->output.size;
    uint16_t len = s->output.len;
    char* ptr = s->output.data + len;

    if (ptr < end)
    {
        if (s->cur_flags)
        {
            *ptr = (char)ConvertToChar(s->cur_flags, s->buf, s->buflen);
            ptr++;
        }
        else
        {
            int copy_len = 0;

            if ((end - ptr) < s->buflen)
                copy_len = end - ptr;
            else
                copy_len = s->buflen;

            memcpy(ptr, s->buf, copy_len);
            ptr = ptr + copy_len;
        }
    }

    s->output.len = (ptr -start);
    s->cur_flags = 0;
    s->buflen = 0;
}

static int SFCC_exec(SFCCState* s, ActionSFCC a, int c)
{
    int iRet = RET_OK;
    switch (a)
    {
    case SFCC_ACT_NOP:
        break;
    case SFCC_ACT_QUIT:
        WriteDecodedSFCC(s);
        iRet = RET_QUIT;
        break;
    case SFCC_ACT_INV:
        WriteDecodedSFCC(s);
        iRet = RET_INV;
        break;
    case SFCC_ACT_DEC:
        if ( s->buflen < MAX_BUF)
        {
            s->buf[s->buflen] = c;
            s->buflen++;
            s->cur_flags = IS_DEC;
        }
        else
        {
            s->cur_flags = 0;
            WriteDecodedSFCC(s);
        }
        break;
    case SFCC_ACT_OCT:
        if ( s->buflen < MAX_BUF)
        {
            s->buf[s->buflen] = c;
            s->buflen++;
            s->cur_flags = IS_OCT;
        }
        else
        {
            s->cur_flags = 0;
            WriteDecodedSFCC(s);
        }
        break;
    case SFCC_ACT_HEX:
        if ( s->buflen < MAX_BUF)
        {
            s->buf[s->buflen] = c;
            s->buflen++;
            s->cur_flags = IS_HEX;
        }
        else
        {
            s->cur_flags = 0;
            WriteDecodedSFCC(s);
        }
        break;
    case SFCC_ACT_COMMA:
    case SFCC_ACT_SPACE:
        WriteDecodedSFCC(s);
        s->cur_flags = 0;
        break;
    default:
        break;
    }

    s->alert_flags |= s->cur_flags;
    return iRet;
}

static int SFCC_scan_fsm(SFCCState* s, int c)
{
    int indexed = 0;
    int value = 0;
    int uc;
    const JSNorm* m = sfcc_norm + s->fsm;

    uc = toupper(c);

    if (isspace(c))
        return (SFCC_exec(s, SFCC_ACT_SPACE, c));

    value = valid_chars[uc];

    if (value)
        indexed = 1;

    do
    {
        if ( !m->event || ((indexed && ((m->event & value) == m->event)) || ( m->event == uc)))
        {
            s->fsm = m->match;
            break;
        }
        s->fsm = m->other;
        m = sfcc_norm + s->fsm;
    }
    while ( true );

    return(SFCC_exec(s, (ActionSFCC)m->action, c));
}

static void StringFromCharCodeDecode(
    const char* src, uint16_t srclen, const char** ptr, char** dst, size_t dst_len,
    uint16_t* bytes_copied, JSState* js, uint8_t* iis_unicode_map)
{
    const char* start = src;
    const char* end = src + srclen;

    SFCCState s;
    s.buflen = 0;
    s.fsm = 0;
    s.output.data = *dst;
    s.output.size = dst_len;
    s.output.len = 0;
    s.cur_flags = s.alert_flags = 0;

    while (!outBounds(start, end, *ptr))
    {
        int iRet = SFCC_scan_fsm(&s, **ptr);

        if (iRet != RET_OK)
        {
            if ( (iRet == RET_INV) && ((*ptr - 1) > start ))
                (*ptr)--;

            break;
        }
        (*ptr)++;
    }

    uint16_t alert = s.alert_flags;

    //alert mixed encodings
    if (alert != ( alert & -alert))
    {
        js->alerts |= ALERT_MIXED_ENCODINGS;
    }
    UnescapeDecode(s.output.data, s.output.len, (const char**)&(s.output.data), &s.output.data,
        s.output.size, &(s.output.len), js, iis_unicode_map);

    *bytes_copied = s.output.len;
}

static void WriteDecodedUnescape(UnescapeState* s, int c, JSState* js)
{
    const char* dstart, * dend;
    char* dptr;

    dstart = s->output.data;
    dend = s->output.data + s->output.size;
    dptr = s->output.data + s->output.len;

    CheckWSExceeded(js, &(s->num_spaces));

    if (dptr < dend)
    {
        *dptr = (char)c;
        dptr++;
    }

    s->output.len = dptr - dstart;
}

static int Unescape_exec(UnescapeState* s, ActionUnsc a, int c, JSState* js)
{
    char* cur_ptr;
    int iRet = RET_OK;

    cur_ptr = s->output.data+ s->output.len;

    switch (a)
    {
    case UNESC_ACT_BACKSLASH:
        s->prev_action = (ActionUnsc)0;
        s->alert_flags |= IS_BACKSLASH;
        s->iNorm <<= 4;
        s->iNorm = (s->iNorm | (hex_lookup[c]));
        if ( s->overwrite && (s->overwrite < cur_ptr))
        {
            s->output.len = s->overwrite - s->output.data;
        }
        s->overwrite = nullptr;
        WriteDecodedUnescape(s, s->iNorm, js);
        s->iNorm = 0;
        break;
    case UNESC_ACT_CONV:
        s->prev_action = (ActionUnsc)0;
        s->iNorm <<= 4;
        s->iNorm = (s->iNorm | (hex_lookup[c]));
        WriteDecodedUnescape(s, c, js);
        break;
    case UNESC_ACT_NOP:
        s->prev_action = (ActionUnsc)0;
        s->iNorm = 0;
        s->overwrite = nullptr;
        WriteDecodedUnescape(s, c, js);
        break;
    case UNESC_ACT_PAREN:
        if (s->prev_action == UNESC_ACT_UNESCAPE)
        {
            s->prev_action = (ActionUnsc)0;
            s->multiple_levels++;
        }
        s->iNorm = 0;
        if (s->paren_count > 0)
            WriteDecodedUnescape(s, c, js);
        s->paren_count++;
        break;
    case UNESC_ACT_PERCENT:
        s->prev_action = (ActionUnsc)0;
        s->alert_flags |= IS_PERCENT;
        s->iNorm <<= 4;
        s->iNorm = (s->iNorm | (hex_lookup[c]));
        if ( s->overwrite && (s->overwrite < cur_ptr))
        {
            s->output.len = s->overwrite - s->output.data;
        }
        s->overwrite = nullptr;
        WriteDecodedUnescape(s, s->iNorm, js);
        s->iNorm = 0;
        break;
    case UNESC_ACT_QUIT:
        s->prev_action = (ActionUnsc)0;
        s->iNorm = 0;
        s->overwrite = nullptr;
        if (s->paren_count)
            s->paren_count--;

        if ( s->paren_count == 0 )
            iRet = RET_QUIT;
        else
            WriteDecodedUnescape(s, c, js);
        break;
    case UNESC_ACT_SAVE:
        s->prev_action = (ActionUnsc)0;
        s->iNorm = 0;
        s->overwrite = cur_ptr;
        WriteDecodedUnescape(s, c, js);
        break;
    case UNESC_ACT_SAVE_NOP:
        s->prev_action = (ActionUnsc)0;
        s->iNorm = 0;
        WriteDecodedUnescape(s, c, js);
        break;
    case UNESC_ACT_SPACE:
        s->iNorm = 0;
        if (s->prev_event == '\'' || s->prev_event =='"')
        {
            WriteDecodedUnescape(s, c, js);
            return iRet;
        }
        if ( s->prev_event != ' ')
        {
            WriteDecodedUnescape(s, c, js);
        }
        s->num_spaces++;
        break;
    case UNESC_ACT_UBACKSLASH:
        s->prev_action = (ActionUnsc)0;
        s->alert_flags |= IS_UBACKSLASH;
        s->iNorm <<= 4;
        s->iNorm = (s->iNorm | (hex_lookup[c]));
        if ( s->overwrite && (s->overwrite < cur_ptr))
        {
            s->output.len = s->overwrite - s->output.data;
        }
        s->overwrite = nullptr;

        if ( s->iNorm > 0xff )
        {
            if (s->unicode_map && (s->iNorm <= 0xffff))
            {
                s->iNorm = s->unicode_map[s->iNorm];
                if (s->iNorm == -1)
                    s->iNorm = NON_ASCII_CHAR;
            }
            else
            {
                s->iNorm = NON_ASCII_CHAR;
            }
        }
        WriteDecodedUnescape(s, s->iNorm, js);
        s->iNorm = 0;
        break;
    case UNESC_ACT_UPERCENT:
        s->prev_action = (ActionUnsc)0;
        s->alert_flags |= IS_UPERCENT;
        s->iNorm <<= 4;
        s->iNorm = (s->iNorm | (hex_lookup[c]));
        if ( s->overwrite && (s->overwrite < cur_ptr))
        {
            s->output.len = s->overwrite - s->output.data;
        }
        s->overwrite = nullptr;
        if ( s->iNorm > 0xff )
        {
            if (s->unicode_map && (s->iNorm <= 0xffff))
            {
                s->iNorm = s->unicode_map[s->iNorm];
                if (s->iNorm == -1)
                    s->iNorm = NON_ASCII_CHAR;
            }
            else
            {
                s->iNorm = NON_ASCII_CHAR;
            }
        }
        WriteDecodedUnescape(s, s->iNorm, js);
        s->iNorm = 0;
        break;
    case UNESC_ACT_UNESCAPE:
        /* Save the action and wait till parenthesis to increment the multiple_levels.
         * Only space is allowed between this action and parentheses */
        s->prev_action = a;
        s->iNorm = 0;
        WriteDecodedUnescape(s, c, js);
        break;
    default:
        break;
    }

    s->prev_event = c;
    return iRet;
}

static int Unescape_scan_fsm(UnescapeState* s, int c, JSState* js)
{
    int indexed = 0;
    int value = 0;
    int uc;
    const JSNorm* m = unescape_norm + s->fsm;

    uc = toupper(c);

    if (isspace(c))
    {
        c = uc =' ';
        return(Unescape_exec(s, UNESC_ACT_SPACE, c, js));
    }

    value = valid_chars[uc];

    if (value)
        indexed = 1;

    do
    {
        if ( !m->event || ( ( m->event == uc) || (indexed && ((m->event & value) == m->event))))
        {
            s->fsm = m->match;
            break;
        }
        s->fsm = m->other;
        m = unescape_norm + s->fsm;
    }
    while ( true );

    return(Unescape_exec(s, (ActionUnsc)m->action, c, js));
}

static void UnescapeDecode(const char* src, uint16_t srclen, const char** ptr, char** dst, size_t dst_len,
    uint16_t* bytes_copied, JSState* js, uint8_t* iis_unicode_map)
{
    const char* start = src;
    const char* end = src + srclen;

    UnescapeState s;
    s.iNorm = 0;
    s.fsm = 0;
    s.output.data = *dst;
    s.output.size = dst_len;
    s.output.len = 0;
    s.alert_flags = 0;
    s.prev_event = 0;
    s.prev_action = (ActionUnsc)0;
    s.overwrite = nullptr;
    s.multiple_levels = 1;
    s.unicode_map = iis_unicode_map;
    s.num_spaces = 0;
    s.paren_count = 0;

    while (!outBounds(start, end, *ptr))
    {
        int iRet = Unescape_scan_fsm(&s, **ptr, js);
        if (iRet != RET_OK)
        {
            /*if( (iRet == RET_INV) && ((*ptr - 1) > start ))
                (*ptr)--;*/

            break;
        }
        (*ptr)++;
    }

    uint16_t alert = s.alert_flags;

    //alert mixed encodings
    if (alert != ( alert & -alert))
    {
        js->alerts |= ALERT_MIXED_ENCODINGS;
    }

    if (s.multiple_levels > js->allowed_levels)
    {
        js->alerts |= ALERT_LEVELS_EXCEEDED;
    }

    PNormDecode(s.output.data, s.output.len, s.output.data, s.output.len, bytes_copied, js);
    //*bytes_copied = s.output.len;
}

static inline void WriteJSNormChar(JSNormState* s, int c, JSState* js)
{
    const char* dstart, * dend;
    char* dptr;

    dstart = s->dest.data;
    dend = s->dest.data + s->dest.size;
    dptr = s->dest.data + s->dest.len;

    CheckWSExceeded(js, &(s->num_spaces));

    if (!outBounds(dstart, dend, dptr))
    {
        *dptr = (char)c;
        dptr++;
    }
    s->dest.len = dptr - dstart;
}

static void WriteJSNorm(JSNormState* s, char* copy_buf, uint16_t copy_len, JSState* js)
{
    const char* end, * dstart, * dend;
    char* ptr, * dptr;

    ptr = copy_buf;
    end = copy_buf + copy_len;

    dstart = s->dest.data;
    dend = s->dest.data + s->dest.size;
    dptr = s->dest.data + s->dest.len;

    CheckWSExceeded(js, &(s->num_spaces));

    if (ptr < end)
    {
        if ((dend - dptr) < copy_len )
        {
            copy_len = dend - dptr;
        }
        memcpy(dptr, ptr, copy_len);
        dptr = dptr + copy_len;
    }

    s->dest.len = dptr - dstart;
}

static int JSNorm_exec(JSNormState* s, ActionJSNorm a, int c, const char* src, uint16_t srclen,
    const char** ptr, JSState* js)
{
    char* cur_ptr;
    int iRet = RET_OK;
    uint16_t bcopied = 0;
    // FIXIT-M this is large for stack. Move elsewhere.
    char decoded_out[65535];
    char* dest = decoded_out;

    cur_ptr = s->dest.data+ s->dest.len;
    switch (a)
    {
    case ACT_NOP:
        WriteJSNormChar(s, c, js);
        break;
    case ACT_SAVE:
        s->overwrite = cur_ptr;
        WriteJSNormChar(s, c, js);
        break;
    case ACT_SPACE:
        if ( s->prev_event != ' ')
        {
            WriteJSNormChar(s, c, js);
        }
        s->num_spaces++;
        break;
    case ACT_UNESCAPE:
        if (s->overwrite && (s->overwrite < cur_ptr))
        {
            s->dest.len = s->overwrite - s->dest.data;
        }
        UnescapeDecode(src, srclen, ptr, &dest, sizeof(decoded_out), &bcopied, js, s->unicode_map);
        WriteJSNorm(s, dest, bcopied, js);
        break;
    case ACT_SFCC:
        if ( s->overwrite && (s->overwrite < cur_ptr))
        {
            s->dest.len = s->overwrite - s->dest.data;
        }
        StringFromCharCodeDecode(src, srclen, ptr, &dest, sizeof(decoded_out), &bcopied, js, s->unicode_map);
        WriteJSNorm(s, dest, bcopied, js);
        break;
    case ACT_QUIT:
        iRet = RET_QUIT;
        WriteJSNormChar(s, c, js);
        break;
    default:
        break;
    }

    s->prev_event = c;

    return iRet;
}

static int JSNorm_scan_fsm(JSNormState* s, int c, const char* src, uint16_t srclen, const char** ptr,
    JSState* js)
{
    char uc;
    const JSNorm* m = javascript_norm + s->fsm;

    uc = toupper(c);

    if (isspace(c))
    {
        c = uc =' ';
        return(JSNorm_exec(s, ACT_SPACE, c, src, srclen, ptr, js));
    }

    do
    {
        if (!m->event || (m->event == uc))
        {
            s->fsm = m->match;
            break;
        }
        s->fsm = m->other;
        m = javascript_norm + s->fsm;
    }
    while ( true );

    return(JSNorm_exec(s, (ActionJSNorm)m->action, c, src, srclen, ptr, js));
}

int JSNormalizeDecode(const char* src, uint16_t srclen, char* dst, uint16_t destlen, const char** ptr,
    int* bytes_copied, JSState* js, uint8_t* iis_unicode_map)
{
    int iRet = RET_OK;
    const char* start, * end;
    JSNormState s;

    if (js == nullptr)
    {
        return RET_QUIT;
    }

    start = src;
    end = src + srclen;

    s.fsm = 0;
    s.overwrite = nullptr;
    s.dest.data = dst;
    s.dest.size = destlen;
    s.dest.len = 0;
    s.prev_event = 0;
    s.unicode_map = iis_unicode_map;
    s.num_spaces = 0;

    while (!outBounds(start, end, *ptr))
    {
        iRet = JSNorm_scan_fsm(&s, **ptr, src, srclen, ptr, js);
        if (iRet != RET_OK)
        {
            break;
        }
        (*ptr)++;
    }

    if (!outBounds(start, end, *ptr) && (iRet == RET_QUIT))
    {
        (*ptr)++;
    }

    //dst = s.dest.data; FIXIT-L dead store; should be?
    *bytes_copied = s.dest.len;

    return RET_OK;
}

/*
int main(int argc, char *argv[])
{
    FILE *iFile = NULL;
    FILE *oFile = NULL;
    char input[65535];
    char output[65535];
    int bytes_copied = 0;
    int bytes_read = 0;
    int ret = 0;
    char *ptr = input;
    JSState js;

    if( argc == 3 )
    {
        iFile = fopen(argv[1], "r");
        oFile = fopen(argv[2], "w");
    }

    if(!oFile || !iFile)
    {
        fprintf(stderr, "usage: %s <in_file> <out_file>\n", argv[0]);
        return -1;
    }

    bytes_read = fread(input, 1, sizeof(input), iFile);
    js.allowed_spaces = 3;
    js.allowed_levels = 1;
    js.alerts = 0;

    ret = JSNormalizeDecode(input, bytes_read, output, sizeof(output),&ptr, &bytes_copied, &js, NULL);
    if( ret == RET_OK)
    {
        fwrite( output, 1, bytes_copied, oFile);
        printf("OUTPUT IS %.*s\n",bytes_copied,output);
        printf("REMAINING is %s\n",ptr);
        if( js.alerts & ALERT_MIXED_ENCODINGS )
            printf("ALERT MIXED ENCODINGS\n");
        if(js.alerts & ALERT_SPACES_EXCEEDED)
            printf("ALERT SPACES EXCEEDED\n");
        if(js.alerts & ALERT_LEVELS_EXCEEDED)
            printf("ALERT LEVELS EXCEEDED\n");
    }
    fclose(iFile);
    fclose(oFile);
    return 0;

}*/

}
