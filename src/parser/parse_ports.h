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

// parse_ports.h derived from sfportobject.h by Marc Noron

#ifndef PARSE_PORTS_H
#define PARSE_PORTS_H

#include "ports/port_var_table.h"

//-------------------------------------------------------------------------
// parser
//-------------------------------------------------------------------------

#define POPERR_NO_NAME            1
#define POPERR_NO_ENDLIST_BRACKET 2
#define POPERR_NOT_A_NUMBER       3
#define POPERR_EXTRA_BRACKET      4
#define POPERR_NO_DATA            5
#define POPERR_ADDITEM_FAILED     6
#define POPERR_MALLOC_FAILED      7
#define POPERR_INVALID_RANGE      8
#define POPERR_DUPLICATE_ENTRY    9
#define POPERR_BOUNDS             10
#define POPERR_BAD_VARIABLE       11

#define POP_MAX_BUFFER_SIZE 256

struct PortObject;

struct POParser
{
    const char* s;          /* current string pointer */
    int slen;         /* bytes left in string */
    int pos;          /* position in string of last GetChar() */
    char token[POP_MAX_BUFFER_SIZE+4];   /* single number, or range, or not flag */
    int errflag;
    /* for handling PortObject references when parsing */
    PortObject* po_ref;
    SF_LNODE* poi_pos;
    PortVarTable* pvTable;
};

PortObject* PortObjectParseString(
    PortVarTable* pvTable, POParser* pop, const char* name,  const
    char* s,int nameflag);

const char* PortObjectParseError(POParser* p);

#endif

