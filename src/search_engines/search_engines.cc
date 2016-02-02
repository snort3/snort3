//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

#ifdef INTEL_SOFT_CPM
extern const BaseApi* se_intel_cpm;
#endif

#ifdef HAVE_HYPERSCAN
extern const BaseApi* se_hyperscan;
#endif

#ifdef STATIC_SEARCH_ENGINES
extern const BaseApi* se_ac_banded;
extern const BaseApi* se_ac_full;
extern const BaseApi* se_ac_sparse;
extern const BaseApi* se_ac_sparse_bands;
extern const BaseApi* se_ac_std;
#endif

const BaseApi* search_engines[] =
{
    se_ac_bnfa,

#ifdef INTEL_SOFT_CPM
    se_intel_cpm,
#endif

#ifdef HAVE_HYPERSCAN
    se_hyperscan,
#endif

#ifdef STATIC_SEARCH_ENGINES
    se_ac_banded,
    se_ac_full,
    se_ac_sparse,
    se_ac_sparse_bands,
    se_ac_std,
#endif

    nullptr
};

