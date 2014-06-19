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
// config_options.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "converter.h"
#include "snort2lua_util.h"



static inline bool open_table_add_option(Converter* cv, 
                                            std::string table_name, 
                                            std::string opt_name, 
                                            bool val)
{
    bool tmpval = cv->open_table(table_name);
    tmpval = cv->add_option_to_table(opt_name, val) && tmpval;
    cv->close_table();
    return tmpval;
}

/*********************************************
 ************  config paf_max ****************
 *********************************************/

namespace {

class PafMax : public ConversionState
{
public:
    PafMax(Converter* cv)  : ConversionState(cv) {};
    virtual ~PafMax() {};
    virtual bool convert(std::stringstream& data_stream);
};

} // namespace


bool PafMax::convert(std::stringstream& data_stream)
{
    cv->open_table("stream_tcp");
    bool retval = parse_int_option("paf_max", data_stream);
    cv->close_table();
    return retval;
}

/*******  A P I ***********/

static ConversionState* paf_max_ctor(Converter* cv)
{
    return new PafMax(cv);
}

static const ConvertMap config_paf_max = 
{
    "paf_max",
    paf_max_ctor,
};


const ConvertMap* paf_max_map = &config_paf_max;


/*********************************************
 *******  Autogenerate Decoder Rules *********
 *********************************************/

static ConversionState* autogenerate_preprocessor_decoder_rules_ctor(Converter* cv)
{
    open_table_add_option(cv, "ips", "enable_builtin_rules", true);
    return nullptr;
}

static const ConvertMap config_autogenerate_decode_rules = 
{
    "autogenerate_preprocessor_decoder_rules",
    autogenerate_preprocessor_decoder_rules_ctor,
};

const ConvertMap* autogenerate_decode_rules_map = &config_autogenerate_decode_rules;



/*********************************************
 *************  Checksum  ********************
 *********************************************/

namespace {

class Checksum : public ConversionState
{
public:
    Checksum(Converter* cv)  : ConversionState(cv) {};
    virtual ~Checksum() {};
    virtual bool convert(std::stringstream& data_stream);
};

} // namespace


bool Checksum::convert(std::stringstream& data_stream)
{
    cv->open_table("nework");
    bool retval = parse_string_option("checksum_eval", data_stream);
    cv->close_table();
    return retval;
}

/*******  A P I ***********/

static ConversionState* checksum_ctor(Converter* cv)
{
    return new Checksum(cv);
}

static const ConvertMap config_checksum =
{
    "checksum_mode",
    checksum_ctor,
};


const ConvertMap* checksum_map = &config_checksum;
