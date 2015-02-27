//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

#ifndef IPS_PCRE_H
#define IPS_PCRE_H

#include <stdint.h>
#include <pcre.h>

struct PcreData
{
    pcre* re;           /* compiled regex */
    pcre_extra* pe;     /* studied regex foo */
    int options;        /* sp_pcre specfic options (relative & inverse) */
    char* expression;
};

PcreData* pcre_get_data(void*);
bool pcre_next(PcreData*);

struct SnortConfig;
void pcre_setup(SnortConfig*);
void pcre_cleanup(SnortConfig*);

#endif

