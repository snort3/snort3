//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2012-2013 Sourcefire, Inc.
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
** Author(s):  Hui Cao <huica@cisco.com>
**
** NOTES
** 5.25.12 - Initial Source Code. Hui Cao
*/

#ifndef FILE_SERVICE_H
#define FILE_SERVICE_H

#include "libs/file_lib.h"

/* Initialize file API, this must be called when snort restarts */
void init_fileAPI(void);

void FileAPIPostInit(void);

/* Close file API, this must be called when snort exits */
void close_fileAPI(void);

/* Get current file context */
FileContext* get_current_file_context(Flow* flow);

#endif

