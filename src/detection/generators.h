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

#ifndef GENERATORS_H
#define GENERATORS_H

// FIXIT migrate all defines to respective modules and delete this file

#define GENERATOR_SNORT_ENGINE        1

#define GENERATOR_TAG                 2
#define TAG_LOG_PKT                   1

#define GENERATOR_INTERNAL          135
#define INTERNAL_EVENT_SYN_RECEIVED   1
#define INTERNAL_EVENT_SESSION_ADD    2
#define INTERNAL_EVENT_SESSION_DEL    3

#define GENERATOR_SPP_REPUTATION    136

#endif

