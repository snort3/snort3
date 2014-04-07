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
 * hi_reqmethod_check.h: Structure definitions/function prototype(s)
 * 		      for the request method type check
 */

/* $Id */

#ifndef HI_REQMETHOD_CHECK_H
#define HI_REQMETHOD_CHECK_H

#define HI_RMFLG_CLEAR		(0x0)
#define HI_RMFLG_GET		(0x1)
#define HI_RMFLG_HEAD		(0x2)
#define HI_RMFLG_POST		(0x4)
#define HI_RMFLG_PUT		(0x8)
#define HI_RMFLG_DELETE		(0x10)
#define HI_RMFLG_TRACE		(0x20)
#define HI_RMFLG_CONNECT	(0x40)
#define HI_RMFLG_ALL		(0xFFFFFFFF)

/* Structure stored as callback data for use by request method
 * detection plugin code.
 */
typedef struct _ReqMethodCheckData 
{
	int type_vector;
} ReqMethodCheckData;

/* Function prototype(s) */
extern int  ReqMethodCheckInit( char*, char*, void** );
extern int  ReqMethodCheckEval( void*, uint8_t**, void* );

#endif /* HI_REQMETHOD_CHECK */
