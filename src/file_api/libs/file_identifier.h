/*
**
**
** Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
**  Copyright (C) 2012-2013 Sourcefire, Inc.
**
**  This program is free software; you can redistribute it and/or modify
**  it under the terms of the GNU General Public License Version 2 as
**  published by the Free Software Foundation.  You may not use, modify or
**  distribute this program under any other version of the GNU General
**  Public License.
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  along with this program; if not, write to the Free Software
**  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
**
**  Author(s):  Hui Cao <hcao@sourcefire.com>
**
**  NOTES
**  5.25.2012 - Initial Source Code. Hcao
*/

#ifndef FILE_IDENTIFIER_H
#define FILE_IDENTIFIER_H
#include "file_lib.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define MAX_BRANCH (UINT8_MAX + 1)

typedef enum _IdNodeState
{
    ID_NODE_NEW,
    ID_NODE_USED,
    ID_NODE_SHARED
} IdNodeState;

typedef struct _IdentifierNode
{
    uint32_t type_id;       /* magic content to match*/
    IdNodeState state;
    uint32_t offset;            /* offset from file start */
    struct _IdentifierNode *next[MAX_BRANCH]; /* pointer to an array of 256 identifiers pointers*/

} IdentifierNode;

typedef struct _IdentifierNodeHead
{
    int offset;            /* offset from file start */
    IdentifierNode *start;  /* start node for the trie at this offset*/
    struct _IdentifierNodeHead *nextHead; /* pointer to next offset head*/

} IdentifierNodeHead;

void init_file_identifers(void);
void insert_file_rule(RuleInfo *rule, void *conf);
uint32_t memory_usage_identifiers(void);

uint32_t find_file_type_id(uint8_t *buf, int len, FileContext *context);

#ifdef DEBUG_MSGS
void print_identifiers(IdentifierNode*);
char *test_find_file_type(void *conf);
#endif

#endif

