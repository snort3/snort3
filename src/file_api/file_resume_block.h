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
**  Author(s):  Hui Cao <hcao@sourcefire.com>
**
**  NOTES
**  9.25.2012 - Initial Source Code. Hcao
*/

#ifndef FILE_RESUME_BLOCK_H
#define FILE_RESUME_BLOCK_H

#include "protocols/packet.h"
#include "file_api.h"

void file_resume_block_init(void);
void file_resume_block_cleanup(void);
int file_resume_block_add_file(void *pkt, uint32_t file_sig, uint32_t timeout,
        File_Verdict verdict, uint32_t file_type_id, uint8_t *signature);
File_Verdict file_resume_block_check(void *pkt, uint32_t file_sig);

#endif 
