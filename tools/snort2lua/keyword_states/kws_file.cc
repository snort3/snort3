//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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
// kws_file.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace keywords
{
namespace
{
static bool printed_error = false;

class File : public ConversionState
{
public:
    File(Converter& c) : ConversionState(c) { }
    virtual ~File() { }
    virtual bool convert(std::istringstream& data);

private:
};
} // namespace

bool File::convert(std::istringstream& data_stream)
{
    // No changes have been made to file. This class literally
    // copies the entire buffer into a rule.

    std::string data = data_stream.str();
    rule_api.add_hdr_data(data);
    data_stream.setstate(std::ios_base::eofbit);
    rule_api.make_rule_a_comment();

    if (!printed_error)
    {
        printed_error = true;
        rule_api.add_comment("WARNING: file keyword is currently unsupported");
    }

    return true;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{ return new File(c); }

static const ConvertMap keyword_file =
{
    "file",
    ctor,
};

const ConvertMap* file_map = &keyword_file;
} // namespace keywords

