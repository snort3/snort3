//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2012-2013 Sourcefire, Inc.
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
/*
** Author(s):  Hui Cao <huica@cisco.com>
**
** NOTES
** 5.05.2012 - Initial Source Code. Hui Cao
*/

#include "file_module.h"

#include "main/snort_config.h"

bool FileIdModule::set(const char*, Value& v, SnortConfig* sc)
{
    FileConfig& fc = sc->file_config;

    FilePolicy& fp = fc.get_file_policy();

    if ( v.is("type_depth") )
        fc.file_type_depth = v.get_long();

    else if ( v.is("signature_depth") )
        fc.file_signature_depth = v.get_long();

    else if ( v.is("block_timeout") )
        fc.file_block_timeout = v.get_long();

    else if ( v.is("lookup_timeout") )
        fc.file_lookup_timeout = v.get_long();

    else if ( v.is("block_timeout_lookup") )
        fc.block_timeout_lookup = v.get_bool();

    else if ( v.is("capture_memcap") )
        fc.capture_memcap = v.get_long();

    else if ( v.is("capture_max_size") )
        fc.capture_max_size = v.get_long();

    else if ( v.is("capture_min_size") )
        fc.capture_min_size = v.get_long();

    else if ( v.is("capture_block_size") )
        fc.capture_block_size = v.get_long();

    else if ( v.is("enable_type") )
    {
        if ( v.get_bool() )
        {
            fp.set_file_type(true);
        }
    }
    else if ( v.is("enable_signature") )
    {
        if ( v.get_bool() )
        {
            fp.set_file_signature(true);
        }
    }
    else if ( v.is("enable_capture") )
    {
        if ( v.get_bool() )
        {
            fp.set_file_capture(true);
        }
    }
    else if ( v.is("show_data_depth") )
        FileConfig::show_data_depth = v.get_long();

    else if ( v.is("trace_type") )
        FileConfig::trace_type = v.get_bool();

    else if ( v.is("trace_signature") )
        FileConfig::trace_signature = v.get_bool();

    else if ( v.is("trace_stream") )
        FileConfig::trace_stream = v.get_bool();

    else if ( v.is("file_rules") )
        return true;

    else if ( v.is("rev") )
        rule.rev = v.get_long();

    else if ( v.is("msg") )
        rule.message = v.get_string();

    else if ( v.is("type") )
        rule.type = v.get_string();

    else if ( v.is("id") )
        rule.id = v.get_long();

    else if ( v.is("category") )
        rule.category = v.get_string();

    else if ( v.is("version") )
        rule.version = v.get_string();

    else if ( v.is("magic") )
        return true;

    else if ( v.is("content") )
        magic.content_str = v.get_string();

    else if ( v.is("offset") )
        magic.offset = v.get_long();

    else if ( v.is("file_policy") )
        return true;

    else if ( v.is("when") )
        return true;

    else if ( v.is("file_type_id") )
        file_rule.when.type_id = v.get_long();

    else if ( v.is("sha256") )
        file_rule.when.sha256 = v.get_string();

    else if ( v.is("use") )
        return true;

    else if ( v.is("verdict") )
        file_rule.use.verdict = (FileVerdict)v.get_long();

    else if ( v.is("enable_file_type") )
        file_rule.use.type_enabled = v.get_bool();

    else if ( v.is("enable_file_signature") )
        file_rule.use.signature_enabled = v.get_bool();

    else if ( v.is("enable_file_capture") )
        file_rule.use.capture_enabled = v.get_bool();

    else
        return false;

    return true;
}

bool FileIdModule::begin(const char* fqn, int idx, SnortConfig*)
{
    if (!idx)
        return true;

    if ( !strcmp(fqn, "file_id.file_rules") )
    {
        rule.clear();
    }
    else if ( !strcmp(fqn, "file_id.file_rules.magic") )
    {
        magic.clear();
    }
    else if ( !strcmp(fqn, "file_id.file_policy") )
    {
        file_rule.clear();
    }

    return true;
}

bool FileIdModule::end(const char* fqn, int idx, SnortConfig* sc)
{
    FileConfig& fc = sc->file_config;

    if (!idx)
        return true;

    if ( !strcmp(fqn, "file_id.file_rules") )
    {
        fc.process_file_rule(rule);
    }
    else if ( !strcmp(fqn, "file_id.file_rules.magic") )
    {
        fc.process_file_magic(magic);
        rule.file_magics.push_back(magic);
    }
    else if ( !strcmp(fqn, "file_id.file_policy") )
    {
        fc.process_file_policy_rule(file_rule);
    }

    return true;
}
