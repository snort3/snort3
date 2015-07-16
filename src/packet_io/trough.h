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

#ifndef TROUGH_H
#define TROUGH_H

// Trough provides access to sources (interface, file, etc.).

enum SourceType
{
    SOURCE_FILE_LIST,  // a file containing a list of sources
    SOURCE_LIST,       // a list of sources (eg from cmd line)
    SOURCE_DIR         // a directory of sources; often used wiht filter
};

void Trough_SetLoopCount(long int);
long Trough_GetLoopCount();
void Trough_SetFilter(const char*);
void Trough_Multi(SourceType, const char* list);
void Trough_SetUp(void);
int Trough_CleanUp(void);
const char* Trough_First(void);
bool Trough_Next(void);
unsigned Trough_GetFileCount();
unsigned Trough_GetQCount();

#endif

