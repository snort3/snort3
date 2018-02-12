//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

namespace preprocessors
{
namespace dce
{
extern std::string transport[5];

class DcerpcServer : public ConversionState
{
public:
    DcerpcServer(Converter& c);
    bool convert(std::istringstream& data_stream) override;
    static int get_binding_id()
    { return binding_id; }

private:
    bool get_bracket_list(std::istringstream& data_stream, std::string& list);
    bool convert_val_or_list(std::istringstream& data_stream, std::string& str);
    bool parse_smb_file_inspection(std::istringstream& data_stream);
    bool parse_detect(std::istringstream& data_stream, std::map<std::string, Binder*> bind, bool
        is_detect);
    void add_default_ports(const std::string& type, std::map<std::string, Binder*> bind);
    bool parse_and_add_ports(const std::string& ports, const std::string& type,  std::map<std::string,
        Binder*> bind, bool bind_port_to_tcp);
    bool init_net_created_table();
    bool init_new_tables(bool is_default);
    bool parse_nets(std::istringstream& data_stream, std::map<std::string,
        Binder*> bind);
    bool add_option_to_transports(const std::string& option, const std::string& value, bool co_only);
    std::map<std::string, bool> detect_ports_set;
    std::map<std::string, bool> autodetect_ports_set;
    std::map<std::string, std::string> table_name;
    static int binding_id;
};

bool add_option_to_table(
    TableApi&, const std::string& table_name, const std::string& option, const std::string& val);

bool add_option_to_table(
    TableApi&, const std::string& table_name, const std::string& option, const int val);

bool add_option_to_table(
    TableApi&, const std::string& table_name, const std::string& option, const bool val);

bool add_deleted_comment_to_table(
    TableApi&, const std::string& table_name, const std::string& option);
} // namespace dce
} // namespace preprocessors

#endif

