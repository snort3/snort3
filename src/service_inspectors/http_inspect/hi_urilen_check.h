/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2005-2013 Sourcefire, Inc.
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
 * hi_urilen_check.h: Structure definitions/function prototype(s)
 * 		      for the URI length detection plugin.
 */

/* $Id */

#ifndef HI_URILEN_CHECK_H
#define HI_URILEN_CHECK_H

#define URILEN_OP_GT	(0x1)
#define URILEN_OP_LT	(0x2)
#define URILEN_OP_EQ	(0x3)
#define URILEN_OP_RANGE (0x4)

/* Structure stored as callback data for use by URILEN 
 * detection plugin code.
 */
typedef struct _UriLenCheckData 
{
    int urilen;
    int urilen2;
    char op;
} UriLenCheckData;

/* Function prototype(s) */
extern int  UriLenCheckInit( char*, char*, void** );
extern int  UriLenCheckEval( void*, uint8_t**, void* );

#endif /* HI_URILEN_CHECK_H */
