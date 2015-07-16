//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2008-2013 Sourcefire, Inc.
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

#ifndef RULE_OPTION_TYPES_H
#define RULE_OPTION_TYPES_H

// RULE_OPTION_* is what is left from the original code which gave each
// option a unique type.  the goal is put everything in the 'other'
// category which means they are handled generically and this whole type
// can be eliminated.  however, content, flowbits, and pcre still
// require special handling.

enum option_type_t
{
    RULE_OPTION_TYPE_LEAF_NODE,
    RULE_OPTION_TYPE_CONTENT,
    RULE_OPTION_TYPE_FLOWBIT,
    RULE_OPTION_TYPE_IP_PROTO,  // FIXIT-L this can be converted to other now
    RULE_OPTION_TYPE_PCRE,
    RULE_OPTION_TYPE_OTHER
};

#endif

