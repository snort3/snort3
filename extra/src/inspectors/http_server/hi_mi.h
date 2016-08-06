//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2003-2013 Sourcefire, Inc.
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
**  @file       hi_mi.h
**
**  @author     Daniel Roelker <droelker@atlas.cs.cuc.edu>
**
**  @brief      Contains the functions in hi_mi.h.  Not much
**
**  NOTES:
**    - 3.2.03:  Initial Development.  DJR
*/
#ifndef HI_MI_H
#define HI_MI_H

#include <sys/types.h>

#include "hi_si.h"
#include "hi_main.h"

int hi_mi_mode_inspection(HI_SESSION* session, int iInspectMode, Packet* p, HttpSessionData*);

#endif

