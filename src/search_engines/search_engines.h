//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

#ifndef SEARCH_ENGINES_H
#define SEARCH_ENGINES_H

struct BaseApi;

extern const BaseApi* search_engines[];

extern const BaseApi* se_ac_banded;
extern const BaseApi* se_ac_full;
extern const BaseApi* se_ac_full_q;
extern const BaseApi* se_ac_sparse;
extern const BaseApi* se_ac_sparse_bands;
extern const BaseApi* se_ac_std;

#endif

