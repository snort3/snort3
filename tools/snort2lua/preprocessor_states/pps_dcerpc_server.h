//--------------------------------------------------------------------------
// Copyright (C) 2016-2016 Cisco and/or its affiliates. All rights reserved.
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
// pps_dcerpc_server.h author Maya Dagon <mdagon@cisco.com>

#ifndef PPS_DCERPC_SERVER_H
#define PPS_DCERPC_SERVER_H

#include <map>

#include "conversion_state.h"
#include "helpers/s2l_util.h"
#include "helpers/util_binder.h"

namespace preprocessors
{
namespace dce
{
extern std::string transport[2];

class DcerpcServer : public ConversionState
{
public:
    DcerpcServer(Converter& c);
    virtual ~DcerpcServer() { }
    virtual bool convert(std::istringstream& data_stream);
    static int get_binding_id()
    { return binding_id; }

private:
    bool get_bracket_list(std::istringstream& data_stream, std::string& list);
    bool convert_val_or_list(std::istringstream& data_stream, std::string& str);
    bool parse_smb_file_inspection(std::istringstream& data_stream);
    bool parse_detect(std::istringstream& data_stream, std::map<std::string, Binder*> bind, bool
        is_detect);
    void add_default_ports(std::string type, std::map<std::string, Binder*> bind);
    void add_default_autodetect_ports(std::string type, std::map<std::string, Binder*> bind);
    bool parse_and_add_ports(std::string ports, std::string type,  std::map<std::string,
        Binder*> bind, bool is_detect);
    bool init_net_created_table();
    bool init_new_tables(bool is_default);
    bool parse_nets(std::istringstream& data_stream, std::map<std::string,
        Binder*> bind);
    bool add_option_to_all_transports(std::string option, std::string value);
    std::map<std::string, bool> detect_ports_set;
    std::map<std::string, bool> autodetect_ports_set;
    std::map<std::string, std::string> table_name;
    static int binding_id;
};

bool add_option_to_table(
    TableApi&, std::string table_name, std::string option, const std::string val);

bool add_option_to_table(
    TableApi&, std::string table_name, std::string option, const int val);

bool add_option_to_table(
    TableApi&, std::string table_name, std::string option, const bool val);
} // namespace dce
} // namespace preprocessors

#endif

