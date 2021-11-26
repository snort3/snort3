//--------------------------------------------------------------------------
// Copyright (C) 2021 Cisco and/or its affiliates. All rights reserved.
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

// file_olefile.h author Vigneshwari Viswanathan vignvisw@cisco.com

#ifndef FILE_OLE_H
#define FILE_OLE_H

#include "file_oleheader.h"

#include <memory>
#include <unordered_map>

#include "detection/detection_engine.h"
#include "helpers/literal_search.h"
#include "ips_options/ips_vba_data.h"
#include "main/snort_debug.h"
#include "utils/util.h"
#include "utils/util_utf.h"

#define OLE_MAX_FILENAME_LEN_UTF16  64
#define OLE_MAX_FILENAME_ASCII      32

#define OLE_HEADER_LEN             512
#define DIR_ENTRY_SIZE             128
#define ROOT_ENTRY             "Root Entry"

#define SIG_COMP_CONTAINER        0x01
#define VBA_COMPRESSION_WINDOW    4096
#define MAX_VBA_BUFFER_LEN       16384

#define INVALID_SECTOR              -1

#define DIR_FILE_TYPE_OFFSET        66
#define DIR_COLOR_OFFSET            67
#define DIR_LEFT_SIB_OFFSET         68
#define DIR_RIGHT_SIB_OFFSET        72
#define DIR_ROOT_NODE_OFFSET        76
#define DIR_CLS_ID_OFFSET           80
#define DIR_STARTING_SEC_OFFSET    116
#define DIR_STREAM_SIZE_OFFSET     120
#define DIR_NEXT_ENTR_OFFSET       128

#define CURRENT_PACKET snort::DetectionEngine::get_current_packet()

#define VBA_DEBUG(module_name, module_id, log_level, p, ...) \
    trace_logf(log_level, module_name , module_id, p, __VA_ARGS__)

#define memcpy_id(destn, dsize, src, ssize) \
    ((dsize>=ssize) ? memcpy(destn, src, ssize) : memcpy( \
    destn, src, dsize))

enum object_type
{
    EMPTY = 0x00,
    STORAGE = 0x01,
    STREAM = 0x02,
    ROOT_STORAGE = 0x05
};

enum color_flag
{
    RED = 0x00,
    BLACK = 0x01
};

enum sector_type
{
    FAT_SECTOR = 0,
    MINIFAT_SECTOR = 1
};

int32_t cli_readn(const uint8_t*& fd, uint32_t& data_len, void* buff, int32_t count);

struct FileProperty
{
public:
    void set_name(uint8_t* f_name)
    {
        name = (char*)f_name;
    }

    char* get_name()
    {
        return name;
    }

    void set_file_type(const uint8_t* buf)
    {
        file_type = (object_type)*buf;
    }

    object_type get_file_type()
    {
        return file_type;
    }

    void set_color(const uint8_t* buf)
    {
        color = (color_flag)*buf;
    }

    color_flag get_color()
    {
        return color;
    }

    void set_lef_sib_id(const uint8_t* buf, byte_order_endianess endian)
    {
        lef_sib_id = (!endian) ? LETOHL_UNALIGNED(buf) : BETOHL_UNALIGNED(buf);
    }

    int32_t get_lef_sib_id()
    {
        return lef_sib_id;
    }

    void set_rig_sib_id(const uint8_t* buf, byte_order_endianess endian)
    {
        rig_sib_id = (!endian) ? LETOHL_UNALIGNED(buf) : BETOHL_UNALIGNED(buf);
    }

    int32_t get_rig_sib_id()
    {
        return rig_sib_id;
    }

    void set_root_node_id(const uint8_t* buf, byte_order_endianess endian)
    {
        root_node_id = (!endian) ? LETOHL_UNALIGNED(buf) : BETOHL_UNALIGNED(buf);
    }

    int32_t get_root_node_id()
    {
        return root_node_id;
    }

    void set_cls_id(const uint8_t* buf)
    {
        memcpy_id(cls_id, sizeof(cls_id), buf, 16);
    }

    char* get_cls_id()
    {
        return cls_id;
    }

    void set_starting_sector(const uint8_t* buf, byte_order_endianess endian)
    {
        starting_sector = (!endian) ? LETOHL_UNALIGNED(buf) : BETOHL_UNALIGNED(buf);
    }

    int32_t get_starting_sector()
    {
        return starting_sector;
    }

    void set_stream_size(const uint8_t* buf, byte_order_endianess endian)
    {
        stream_size = (!endian) ? LETOHLL_UNALIGNED(buf) : BETOHLL_UNALIGNED(buf);
    }

    int64_t get_stream_size()
    {
        return stream_size;
    }

    FileProperty()
    {
        name = nullptr;
    }

private:
    char* name;
    object_type file_type;
    color_flag color;
    int32_t lef_sib_id;
    int32_t rig_sib_id;
    int32_t root_node_id;
    char cls_id[16];
    int32_t starting_sector;
    int64_t stream_size;
};

class DirectoryList
{
public:
    std::unordered_map<char*, FileProperty*> oleentry;
    snort::UtfDecodeSession* utf_state;

    bool is_file_exists(char* name);
    FileProperty* get_file_node(char* name);
    int32_t get_file_sector(char* name);
    bool is_mini_sector(char* name);
    void set_mini_stream_sector(int32_t mini_stream_sector)
    {
        this->mini_stream_sector = mini_stream_sector;
    }

    int32_t get_mini_stream_sector()
    {
        return mini_stream_sector;
    }

    DirectoryList()
    {
        utf_state = nullptr;
        mini_stream_sector = -1;
    }

    ~DirectoryList();

private:
    int32_t mini_stream_sector;
};

class OleFile
{
public:
    bool parse_ole_header();
    void populate_fat_list();
    void populate_mini_fat_list();
    void walk_directory_list();
    void find_and_extract_vba(uint8_t*&, uint32_t&);
    int32_t get_next_fat_sector(int32_t sec_id);
    int32_t get_next_mini_fat_sector(int32_t sec_id);
    int32_t get_fat_offset(int32_t sec_id);
    int32_t get_mini_fat_offset(int32_t sec_id);
    int32_t get_file_offset(const uint8_t*, uint32_t data_len);
    void get_file_data(char*, uint8_t*&, uint32_t&);

    void decompression(const uint8_t* data, uint32_t& data_len, uint8_t*& buffer,
        uint32_t& buffer_ofset);
    uint32_t find_bytes_to_copy(uint32_t byte_offset, uint32_t data_len,
                                   uint32_t stream_size, uint16_t sector_size);

    int search_nocase(const uint8_t* buffer, unsigned buffer_len) const
    {
        return searcher->search(search_handle, buffer, buffer_len);
    }

    OleFile(const uint8_t* file_buf, const uint32_t buf_len)
    {
        this->file_buf = file_buf;
        this->buf_len = buf_len;
    }

    ~OleFile()
    {
        delete header;
        delete dir_list;
        delete[] fat_list;
        delete[] mini_fat_list;
    }

private:
    const uint8_t* file_buf;
    uint32_t buf_len;

    OleHeader* header = nullptr;
    DirectoryList* dir_list = nullptr;

    int32_t* fat_list = nullptr;
    int32_t fat_list_len = 0;
    int32_t* mini_fat_list = nullptr;
    int32_t mini_fat_list_len = 0;
};

void oleprocess(const uint8_t* const, const uint32_t, uint8_t*&, uint32_t&);
#endif

