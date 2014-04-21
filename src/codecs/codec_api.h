/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2013-2013 Sourcefire, Inc.
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

#ifndef CODECS_H
#define CODECS_H

struct BaseApi;

extern const BaseApi* cd_eth;
extern const BaseApi* cd_ipv4;
extern const BaseApi* cd_ipv6;
extern const BaseApi* cd_icmp4;
extern const BaseApi* cd_icmp6;
extern const BaseApi* cd_tcp;
extern const BaseApi* cd_udp;
extern const BaseApi* cd_esp;
#if 0

#if STATIC_DECODERS

#endif
extern const BaseApi* se_ac_banded;
extern const BaseApi* se_ac_bnfa;
extern const BaseApi* se_ac_bnfa_q;
extern const BaseApi* se_ac_full;
extern const BaseApi* se_ac_full_q;
extern const BaseApi* se_ac_sparse;
extern const BaseApi* se_ac_sparse_bands;
extern const BaseApi* se_ac_std;


extern const BaseApi* search_engines[];



#endif

extern const BaseApi* codecs[];

#endif
