//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

// author Hui Cao <huica@cisco.com>

#ifndef FILE_FLOWS_H
#define FILE_FLOWS_H

// This provides a wrapper to manage several file contexts

#include "flow/flow.h"
#include "main/snort_types.h"

#include "file_api.h"
#include "file_module.h"
#include "file_policy.h"


namespace snort
{
class FileContext;
class Flow;

class FileInspect : public Inspector
{
public:
    FileInspect(FileIdModule*);
    ~FileInspect() override;
    void eval(Packet*) override { }
    bool configure(SnortConfig*) override;
    FileConfig* config;
};

class SO_PUBLIC FileFlows : public FlowData
{
public:

    FileFlows(Flow* f, FileInspect* inspect) : FlowData(file_flow_data_id, inspect), flow(f) { }
    ~FileFlows() override;
    static void init()
    { file_flow_data_id = FlowData::create_flow_data_id(); }

    void handle_retransmit(Packet*) override;

    // Factory method to get file flows
    static FileFlows* get_file_flows(Flow*);
    static FilePolicyBase* get_file_policy(Flow*);

    FileContext* get_current_file_context();

    void set_current_file_context(FileContext*);

    // Get file context based on file id, create it if not existed
    FileContext* get_file_context(uint64_t file_id, bool to_create);

    uint64_t get_new_file_instance();

    void set_file_name(const uint8_t* fname, uint32_t name_size);

    void set_sig_gen_state( bool enable )
    {
        gen_signature = enable;
    }

    void add_pending_file(uint64_t file_id);

    // This is used when there is only one file per session
    bool file_process(const uint8_t* file_data, int data_size, FilePosition,
        bool upload, size_t file_index = 0);

    // This is used for each file context. Support multiple files per session
    bool file_process(uint64_t file_id, const uint8_t* file_data,
        int data_size, uint64_t offset, FileDirection);

    static unsigned file_flow_data_id;

    void set_file_policy(FilePolicyBase* fp) { file_policy = fp; }
    FilePolicyBase* get_file_policy() { return file_policy; }

private:
    void init_file_context(FileDirection, FileContext*);
    FileContext* find_main_file_context(FilePosition, FileDirection, size_t id = 0);
    FileContext* main_context = nullptr;
    FileContext* current_context = nullptr;
    uint64_t current_file_id = 0;
    uint64_t pending_file_id = 0;
    bool gen_signature = false;
    Flow* flow = nullptr;
    FilePolicyBase* file_policy = nullptr;
};
}
#endif

