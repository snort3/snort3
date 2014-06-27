/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2002-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
// rule_content.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "util/converter.h"
#include "rule_states/rule_api.h"
#include "util/util.h"

namespace rules
{

/*
 *  To use this template, declared an 'unchanged_rule_ctor<rule_name>'
 *  in the ConvertMap struct.  Everything else will be taken care of and
 *  all of the data between two semicolons will be placed in the new rule AS IS!!
 *  Examples are below the line marked 'FINISHED TEMPLATES'.
 */

template<const std::string *rule_name>
class UnchangedRuleOption : public ConversionState
{
public:
    UnchangedRuleOption( Converter* cv, LuaData* ld)
        :   ConversionState(cv, ld) 
    { };
    virtual ~UnchangedRuleOption() {};
    
    friend bool set_next_rule_state(std::istringstream& stream, Converter* cv, LuaData* ld);
    virtual bool convert(std::istringstream& stream)
    {
        std::string val;

        std::getline(stream, val, ';');
        bool retval = ld->add_rule_option(*rule_name, val);
        return retval && set_next_rule_state(stream);
    }
};


template<const std::string *rule_name>
static ConversionState* unchange_rule_ctor(Converter* cv, LuaData* ld)
{
    return new UnchangedRuleOption<rule_name>(cv, ld);
}



/****************************************
 *******   FINISHED TEMPLATES ***********
 ****************************************/

/************************************
 **********  M S G ******************
 ************************************/


static const std::string msg = "msg";
static const ConvertMap rule_msg =
{
    msg,
    unchange_rule_ctor<&msg>,
};

const ConvertMap* msg_map = &rule_msg;


/************************************
 **********  G I D ******************
 ************************************/


static const std::string gid = "gid";
static const ConvertMap rule_gid =
{
    gid,
    unchange_rule_ctor<&gid>,
};

const ConvertMap* gid_map = &rule_gid;


/************************************
 **********  S I D  *****************
 ************************************/


static const std::string sid = "sid";
static const ConvertMap rule_sid =
{
    sid,
    unchange_rule_ctor<&sid>,
};

const ConvertMap* sid_map = &rule_sid;


/************************************
 **********  R E V  *****************
 ************************************/


static const std::string rev = "rev";
static const ConvertMap rule_rev =
{
    rev,
    unchange_rule_ctor<&rev>,
};

const ConvertMap* rev_map = &rule_rev;


} // namespace rule
