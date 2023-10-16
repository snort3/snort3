//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

// file_identifier.h author Hui Cao <huica@cisco.com>

#ifndef FILE_IDENTIFIER_H
#define FILE_IDENTIFIER_H

// File type identification is based on file magic. To improve the detection
// performance, a trie is created to scan file data once. Currently, only the
// most specific file type is returned.

#include <list>
#include <vector>

#include "file_lib.h"

namespace snort
{
class GHash;
}

#define MAX_BRANCH (UINT8_MAX + 1)

enum IdNodeState
{
    ID_NODE_NEW,
    ID_NODE_USED,
    ID_NODE_SHARED
};

class FileMeta
{
public:
    FileMeta() { }
    FileMeta(uint type_id, const std::string& type_name, const std::string& file_category, const std::string&
        file_version, const std::vector<std::string>& file_groups)
        : id(type_id), type(type_name),category(file_category),version(file_version),groups(
            file_groups) { }
    void clear();
    uint32_t rev = 0;
    uint32_t id = 0;
    std::string type;
    std::string category;
    std::string version;
    std::vector<std::string> groups;
};

struct IdentifierNode
{
    uint32_t type_id;       /* magic content to match*/
    IdNodeState state;
    uint32_t offset;            /* offset from file start */
    struct IdentifierNode* next[MAX_BRANCH]; /* pointer to an array of 256 identifiers pointers*/
};

typedef std::list<void* >  IDMemoryBlocks;

class FileIdentifier
{
public:
    ~FileIdentifier();
    uint32_t memory_usage() const { return memory_used; }
    void add_file_id(FileMeta& rule);
    uint32_t find_file_type_id(const uint8_t* buf, int len, uint64_t offset, void** context);
    const FileMeta* get_rule_from_id(uint32_t) const;
    void get_magic_rule_ids_from_type(const std::string&, const std::string&,
        snort::FileTypeBitSet&) const;

private:
    void init_merge_hash();
    void* calloc_mem(size_t size);
    void set_node_state_shared(IdentifierNode* start);
    IdentifierNode* clone_node(IdentifierNode* start);
    bool update_next(IdentifierNode* start, IdentifierNode** next_ptr, IdentifierNode* append);
    void update_trie(IdentifierNode* start, IdentifierNode* append);

    /*properties*/
    IdentifierNode* identifier_root = nullptr; /*Root of magic tries*/
    uint32_t memory_used = 0; /*Track memory usage*/
    snort::GHash* identifier_merge_hash = nullptr;
    FileMeta file_magic_rules[FILE_ID_MAX + 1];
    IDMemoryBlocks id_memory_blocks;
};

#endif

