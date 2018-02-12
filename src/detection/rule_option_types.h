//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

// if you change this, you must also update detection_options.cc::option_type_str[].
enum option_type_t
{
    RULE_OPTION_TYPE_LEAF_NODE,    // internal use by rule compiler
    RULE_OPTION_TYPE_BUFFER_SET,   // sets sticky buffer
    RULE_OPTION_TYPE_BUFFER_USE,   // uses sticky buffer
    RULE_OPTION_TYPE_CONTENT,      // ideally would be eliminated (implies _BUFFER_USE)
    RULE_OPTION_TYPE_FLOWBIT,      // ideally would be eliminated
    RULE_OPTION_TYPE_OTHER         // for all new buffer independent rule options
};

#endif

