/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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


#ifndef MSTRING_H
#define MSTRING_H

#include "main/snort_types.h"

/*  D E F I N E S  *******************************************************/
#define TOKS_BUF_SIZE   100


/*  P R O T O T Y P E S  *************************************************/
SO_PUBLIC char ** mSplit(const char *, const char *, const int, int *, const char);
SO_PUBLIC void mSplitFree(char ***toks, int numtoks);
SO_PUBLIC int mContainsSubstr(const char *, int, const char *, int);

#endif  /* MSTRING_H */
