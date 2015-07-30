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

#include "search_engines.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

struct BaseApi;

extern const BaseApi* se_ac_bnfa;
extern const BaseApi* se_ac_bnfa_q;

#ifdef STATIC_IPS_OPTIONS
#ifdef INTEL_SOFT_CPM
extern const BaseApi* se_intel_cpm;
#endif
#endif

const BaseApi* search_engines[] =
{
#ifdef STATIC_IPS_OPTIONS
    se_ac_banded,
    se_ac_full,
    se_ac_full_q,
    se_ac_sparse,
    se_ac_sparse_bands,
    se_ac_std,
#ifdef INTEL_SOFT_CPM
    se_intel_cpm,
#endif
#endif
    se_ac_bnfa,
    se_ac_bnfa_q,
    nullptr
};

