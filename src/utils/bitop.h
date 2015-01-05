/*
** Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2002-2013 Sourcefire, Inc.
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
/*
** Dan Roelker <droelker@sourcefire.com>
** Marc Norton <mnorton@sourcefire.com>
**
** NOTES
**   5.15.02 - Initial Source Code. Norton/Roelker
**   5.23.02 - Moved bitop functions to bitop.h to inline. Norton/Roelker
**   1.21.04 - Added static initialization. Roelker
**   9.13.05 - Separated type and inline func definitions. Sturges
** 
*/

#ifndef BITOP_H
#define BITOP_H

typedef struct _BITOP {
    unsigned char *pucBitBuffer;
    unsigned int  uiBitBufferSize;
    unsigned int  uiMaxBits;
} BITOP;

#endif

