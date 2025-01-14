//--------------------------------------------------------------------------
// Copyright (C) 2025-2025 Cisco and/or its affiliates. All rights reserved.
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
// snort_pcre.h author Michael Matirko <mmatirko@cisco.com>

#ifndef SNORT_PCRE_H
#define SNORT_PCRE_H

// pcre2 code unit width must be set prior to including the pcre2
// headers. Setting it here allows us to not require a redefinition
// of PCRE2_CODE_UNIT_WIDTH everywhere we include pcre2.h

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#endif

