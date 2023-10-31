//--------------------------------------------------------------------------
// Copyright (C) 2021-2023 Cisco and/or its affiliates. All rights reserved.
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

// file_olefile.cc author Vigneshwari Viswanathan vignvisw@cisco.com

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "file_olefile.h"

DirectoryList :: ~DirectoryList()
{
    std::unordered_map<char*, FileProperty*>::iterator it = oleentry.begin();

    while (it != oleentry.end())
    {
        FileProperty* node =  it->second;
        delete[] node->get_name();
        delete node;
        it = oleentry.erase(it);
    }
}

// The function walk_directory_list() will read the entries of all the directory entry
// arrays of an ole file and will create a mapping between the storage/stream name and
// the fileproperty object. Each entry of directory entry array will be of 64 bytes.
//
// The first directory entry array value is obtained from the ole header. The subsequent
// sectors will be obtained by referring the fat list array.
//
// Each object of fileproperty will give us the information about the starting sector of
// that storage/stream, overall size of the stream/storage and other metadata.

// The content of any storage/stream is read by combining all the sectors of that stream/
// storage and it will begin with starting sector value mentioned in fileproperty object.
// Also, this starting sector value can be used to obtain the next sector to read by
// referring the FAT list array.
void OleFile :: walk_directory_list()
{
    int32_t current_sector;
    uint16_t sector_size;
    uint8_t* name_buf;
    int bytes_copied;
    FileProperty* node;
    char* file_name;

    VBA_DEBUG(vba_data_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL, CURRENT_PACKET,
        "Parsing the Directory list.\n");

    current_sector = header->get_first_dir();
    sector_size = header->get_sector_size();

    dir_list = new DirectoryList();

    while (current_sector > INVALID_SECTOR)
    {
        const uint8_t* buf = file_buf;
        uint32_t start_offset = get_fat_offset(current_sector);

        if ((start_offset + sector_size) > buf_len)
            return;

        buf += start_offset;

        int32_t count = 0;

        while (count < (sector_size/DIR_ENTRY_SIZE))
        {
            node = new FileProperty;
            name_buf = new uint8_t[32];

            // The filename is UTF16 encoded and will be of the size 64 bytes.
            snort::UtfDecodeSession utf_state;
            if (!header->get_byte_order())
                utf_state.set_decode_utf_state_charset(CHARSET_UTF16LE);
            else
                utf_state.set_decode_utf_state_charset(CHARSET_UTF16BE);
            utf_state.decode_utf(buf, OLE_MAX_FILENAME_LEN_UTF16, name_buf,
                OLE_MAX_FILENAME_ASCII, &bytes_copied);

            node->set_name(name_buf);

            node->set_file_type(buf + DIR_FILE_TYPE_OFFSET);

            node->set_color(buf + DIR_COLOR_OFFSET);

            node->set_lef_sib_id(buf + DIR_LEFT_SIB_OFFSET, header->get_byte_order());

            node->set_rig_sib_id(buf + DIR_RIGHT_SIB_OFFSET, header->get_byte_order());

            node->set_root_node_id(buf + DIR_ROOT_NODE_OFFSET, header->get_byte_order());

            node->set_cls_id(buf + DIR_CLS_ID_OFFSET);

            node->set_starting_sector(buf + DIR_STARTING_SEC_OFFSET, header->get_byte_order());

            node->set_stream_size(buf + DIR_STREAM_SIZE_OFFSET, header->get_byte_order());

            buf += DIR_NEXT_ENTR_OFFSET;

            //Insert the oleentry
            file_name = (char*)name_buf;

            if (strcmp(file_name, ROOT_ENTRY) == 0)
                dir_list->set_mini_stream_sector(node->get_starting_sector());
            object_type type = node->get_file_type();
            // check for all the empty/non valid entries in the directory list.
            if (!(type == ROOT_STORAGE or type == STORAGE or type == STREAM))
            {
                delete node;
                delete[] name_buf;
            }
            else
                dir_list->oleentry.insert({ file_name, node });
            count++;
        }
        // Reading the next sector of current_sector by referring the FAT list array.
        // A negative number suggests the end of directory entry array and there are
        // no more stream/storage to read.
        int32_t next_sector = get_next_fat_sector(current_sector);
        if (next_sector > INVALID_SECTOR)
            current_sector = next_sector;
        else
            current_sector = INVALID_SECTOR;
    }
    VBA_DEBUG(vba_data_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL, CURRENT_PACKET,
        "End of Directory list parsing.\n");
}

FileProperty* DirectoryList :: get_file_node(char* name)
{
    std::unordered_map<char*, FileProperty*>::iterator it;

    it = oleentry.find(name);

    if (it != oleentry.end())
        return(it->second);
    return nullptr;
}

// Every index of fat_list array is the fat sector ID and the value present
// at that index will be its corresponding next fat sector ID.
int32_t OleFile :: get_next_fat_sector(int32_t sec_id)
{
    if (fat_list and sec_id > INVALID_SECTOR and sec_id < fat_list_len)
        return fat_list[sec_id];
    else
    {
        VBA_DEBUG(vba_data_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL, CURRENT_PACKET,
            "The next sector ID of fat sector %d is not available in fat list.\n", sec_id);
        return INVALID_SECTOR;
    }
}

// Every index of mini_fat_list array is the minifat sector ID and the value present
// at that index will be its corresponding next minifat sector ID.
int32_t OleFile :: get_next_mini_fat_sector(int32_t sec_id)
{
    if (mini_fat_list and sec_id > INVALID_SECTOR and sec_id < mini_fat_list_len)
        return mini_fat_list[sec_id];
    else
    {
        VBA_DEBUG(vba_data_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL, CURRENT_PACKET,
            "The next sector ID of mini fat sector %d is not available in minifat list.\n",
            sec_id);
        return INVALID_SECTOR;
    }
}

// The offset of a sector is header_size + (sector_number * size_of_each_sector).
int32_t OleFile :: get_fat_offset(int32_t sec_id)
{
    int32_t byte_offset;
    byte_offset = OLE_HEADER_LEN + (sec_id * header->get_sector_size());
    return(byte_offset);
}

// Example to get the mini fat sector offset.
// If,
// sector size = 512 bytes
// mini sector size = 64 bytes
// and sector 2 and 5 are storing the mini fat sectors (assuming the mini fat sector is
// starting with sector 2) , then the offset of 12th mini fat sector is calculated as
// below:
//
// mini fat sector per sector = 512 bytes / 64 bytes = 8.
// The first 8 mini fat sectors would be stored in the fat sector 2 and therefore the
// 12th minifat sector would be stored in the next fat sector of sector 2 which is sector
//  5.( we'll get this info from the fat sector array ( get_next_fat_sector() ) where
// sector 5 would be mapped to sector 2 as the next fat sector. -2 will be mapped against
// sector 5, as sector 5 is the last sector storing mini fat sectors )
//
// The 12th mini fat sector would be the 4th ( index = 3) mini fat sector stored in fat sector 5.
//
// The offset of sector 5  = header_size + (sector_size) * 5 = 512 + 512 * 5 = 3072 bytes.
//
// The offset of 12th mini fat sector = (offset of 5th fat sector ) + ( offset of 4th(index is 3)
//  mini fat sector in 5th fat sector)
//                                    =  3072 + 64 * 3
//                                    =  3264 bytes.
int32_t OleFile :: get_mini_fat_offset(int32_t sec_id)
{
    int32_t sec_position, mini_sec_position, count, current_sector;
    int32_t byte_offset, mini_fat_persector;

    mini_fat_persector = header->get_sector_size() / header->get_mini_sector_size();

    if (sec_id >=  mini_fat_persector)
    {
        sec_position = sec_id/mini_fat_persector;
        mini_sec_position = sec_id % mini_fat_persector;
    }
    else
    {
        sec_position = 0;
        mini_sec_position = sec_id;
    }

    count = 0;

    current_sector = dir_list->get_mini_stream_sector();

    while (count < sec_position)
    {
        int32_t next_sector = get_next_fat_sector(current_sector);
        if (next_sector <= INVALID_SECTOR)
            return -1;
        count++;
        current_sector = next_sector;
    }
    byte_offset = OLE_HEADER_LEN + (current_sector * header->get_sector_size()) +
        (mini_sec_position *
        header->get_mini_sector_size());
    return byte_offset;
}

uint32_t OleFile :: find_bytes_to_copy(uint32_t byte_offset, uint32_t data_len,
                                   uint32_t stream_size, uint16_t sector_size)
{
    uint32_t remaining_bytes = stream_size - data_len;
    uint32_t bytes_to_copy;

    if ((byte_offset + sector_size) > buf_len)
    {
        bytes_to_copy = buf_len - byte_offset;
    }
    else
    {
        bytes_to_copy = sector_size;
    }

    if  (bytes_to_copy > remaining_bytes)
        bytes_to_copy = remaining_bytes;

    return bytes_to_copy;
}

void OleFile :: get_file_data(char* file, uint8_t*& file_data, uint32_t& data_len)
{
    FileProperty* node = dir_list->get_file_node(file);
    data_len = 0;

    if (node)
    {
        int32_t starting_sector;
        uint32_t stream_size;
        sector_type is_fat = FAT_SECTOR;
        uint32_t byte_offset, bytes_to_copy;
        uint8_t* temp_data;

        starting_sector = node->get_starting_sector();
        stream_size = node->get_stream_size();

        file_data = new uint8_t[stream_size];
        temp_data = file_data;
        if (stream_size <= header->get_minifat_cutoff())
            is_fat = MINIFAT_SECTOR;

        if (is_fat == FAT_SECTOR)
        {
            int32_t current_sector = starting_sector;
            uint16_t sector_size = header->get_sector_size();
            while (current_sector > INVALID_SECTOR)
            {
                byte_offset = get_fat_offset(current_sector);
                if (byte_offset > buf_len)
                    return;

                bytes_to_copy = find_bytes_to_copy(byte_offset, data_len,
                                    stream_size, sector_size);

                memcpy(temp_data, (file_buf + byte_offset), bytes_to_copy);
                temp_data += bytes_to_copy;
                data_len += bytes_to_copy;

                int32_t next_sector = get_next_fat_sector(current_sector);
                current_sector = next_sector;
            }
        }
        else
        {
            int32_t mini_sector = node->get_starting_sector();
            uint16_t mini_sector_size = header->get_mini_sector_size();
            while (mini_sector > INVALID_SECTOR)
            {
                byte_offset = get_mini_fat_offset(mini_sector);
                if (byte_offset > buf_len)
                    return;

                bytes_to_copy = find_bytes_to_copy(byte_offset, data_len,
                                    stream_size, mini_sector_size);

                memcpy(temp_data, (file_buf + byte_offset), bytes_to_copy);
                temp_data += bytes_to_copy;
                data_len += bytes_to_copy;

                int32_t next_sector = get_next_mini_fat_sector(mini_sector);
                mini_sector =  next_sector;
            }
        }
    }
}

// The function populate_fat_list() reads the contents of FAT array sectors to create
// the the fat_list array where each of the indices represents the current sector
// ID and the value at that index would be its next sector ID.
void OleFile :: populate_fat_list()
{
    int32_t current_sector, fat_sector_curr_cnt = 0;
    int32_t fat_sector = header->get_difat_array(fat_sector_curr_cnt);
    int32_t max_secchain_cnt = header->get_sector_size()/4;
    int32_t count = 0;

    VBA_DEBUG(vba_data_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL, CURRENT_PACKET,
        "Reading the FAT list array.\n");
    fat_list_len = ( header->get_fat_sector_count() * header->get_sector_size() ) / 4;
    if (fat_list_len < 1)
    {
        VBA_DEBUG(vba_data_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL, CURRENT_PACKET,
            "FAT list array is empty.\n");
        return;
    }

    fat_list = new int32_t[fat_list_len];

    memset(fat_list, -1, fat_list_len);

    current_sector = fat_sector;
    while (current_sector > INVALID_SECTOR)
    {
        uint32_t byte_offset = OLE_HEADER_LEN + (current_sector * header->get_sector_size());

        const uint8_t* buf = file_buf;

        buf += byte_offset;

        if ((byte_offset + header->get_sector_size()) > buf_len)
            return;

        while ((count - (fat_sector_curr_cnt * max_secchain_cnt)) < (max_secchain_cnt))
        {
            if (!header->get_byte_order())
                fat_list[count] = LETOHL_UNALIGNED(buf);
            else
                fat_list[count] = BETOHL_UNALIGNED(buf);
            count++;
            buf += 4;
        }
        fat_sector_curr_cnt++;
        if (fat_sector_curr_cnt < MAX_DIFAT_SECTORS)
            current_sector = header->get_difat_array(fat_sector_curr_cnt);
        else
            return;
    }
    VBA_DEBUG(vba_data_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL, CURRENT_PACKET,
        "FAT list array is populated.\n");
}

// The function populate_mini_fat_list() reads the contents of mini FAT array sectors to
// create the the mini_fat_list array where each of the indices represents the
// current mini sector ID and the value at that index would be its next mini
// sector ID.
void OleFile :: populate_mini_fat_list()
{
    int32_t minifat_sector = header->get_first_minifat(), current_sector;

    int32_t max_secchain_cnt = header->get_sector_size()/4;
    int32_t count = 0;

    VBA_DEBUG(vba_data_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL, CURRENT_PACKET,
        "Reading the Mini-FAT list array.\n");
    mini_fat_list_len = ( header->get_minifat_count() * header->get_sector_size() )  / 4;
    if (mini_fat_list_len < 1)
    {
        VBA_DEBUG(vba_data_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL, CURRENT_PACKET,
            "Mini-FAT list array is empty.\n");
        return;
    }

    mini_fat_list = new int32_t[mini_fat_list_len];

    memset(mini_fat_list, -1, mini_fat_list_len);

    current_sector = minifat_sector;
    int32_t minfat_curr_cnt = 0;
    while (current_sector > INVALID_SECTOR)
    {
        uint32_t byte_offset = OLE_HEADER_LEN + (current_sector * header->get_sector_size());

        if ((byte_offset + header->get_sector_size()) > buf_len)
            return;

        const uint8_t* buf = file_buf;

        buf += byte_offset;

        while ((count - (minfat_curr_cnt * max_secchain_cnt)) < max_secchain_cnt)
        {
            if (!header->get_byte_order())
                mini_fat_list[count] = LETOHL_UNALIGNED(buf);
            else
                mini_fat_list[count] = BETOHL_UNALIGNED(buf);
            count++;
            buf += 4;
        }
        minfat_curr_cnt++;
        int32_t next_sector = get_next_fat_sector(current_sector);
        if (next_sector > INVALID_SECTOR)
            current_sector = next_sector;
        else
            current_sector = INVALID_SECTOR;
    }
    VBA_DEBUG(vba_data_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL, CURRENT_PACKET,
        "Mini-FAT list array is populated..\n");
}

// API to parse the OLE File Header.
// The header is always located at the beginning of the file,
// and its size is exactly 512 bytes. This implies that the first
// sector (with SecID 0) always starts at file offset 512.
bool OleFile :: parse_ole_header()
{
    VBA_DEBUG(vba_data_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL, CURRENT_PACKET,
        "Staring the OLE header parsing.\n");
    header = new OleHeader;
    if (!header->set_byte_order(file_buf + HEADER_BYTE_ORDER_OFFSET))
    {
        VBA_DEBUG(vba_data_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL, CURRENT_PACKET,
            "Invalid byte order in the OLE header. Returning.\n");
        return false;
    }

    // Header Signature (8 bytes) is Identification signature of the OLE file,
    // and must be of the value 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1.
    if (!header->match_ole_sig(file_buf))
    {
        VBA_DEBUG(vba_data_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL, CURRENT_PACKET,
            "Invalid file signature of OLE file. Returning.\n");
        return false;
    }

    // Minor Version field should be set to 0x003E.
    header->set_minor_version(file_buf + HEADER_MINOR_VER_OFFSET);

    // Major Version field is set to either 0x0003 (version 3) or 0x0004 (version 4).
    header->set_major_version(file_buf + HEADER_MAJOR_VER_OFFSET);

    // This field specifies the sector size of the compound file as a power of 2.
    header->set_sector_size(file_buf + HEADER_SECTR_SIZE_OFFSET);

    // This field specifies the sector size of the Mini Stream as a power of 2.
    header->set_mini_sector_size(file_buf + HEADER_MIN_SECTR_SIZE_OFFSET);

    header->set_fat_sector_count(file_buf + HEADER_FAT_SECTR_CNT_OFFSET);

    header->set_first_dir(file_buf + HEADER_FIRST_DIR_SECTR_OFFSET);

    header->set_minifat_cutoff(file_buf + HEADER_MINFAT_CUTOFF_OFFSET);

    header->set_first_minifat(file_buf + HEADER_FIRST_MINFAT_OFFSET);

    header->set_minifat_count(file_buf + HEADER_MINFAT_COUNT_OFFSET);

    header->set_first_difat(file_buf + HEADER_FIRST_DIFAT_OFFSET);

    header->set_difat_count(file_buf + HEADER_DIFAT_CNT_OFFSET);

    header->set_dir_sector_count(file_buf + HEADER_DIR_SECTR_CNT_OFFSET);

    // DIFAT array of 32-bit integer fields contains the first 109 FAT sector locations of the
    // compound file.
    header->set_difat_array(file_buf + HEADER_DIFAT_ARRY_OFFSET);

    VBA_DEBUG(vba_data_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL, CURRENT_PACKET,
        "Parsing of OLE header is done.\n");

    return true;
}

// The vba code in a VBA macro file begins with the keyword "ATTRIBUT" .This
// keyword is used to calculate the offset of vba code and is decompressed using
// RLE algorithm.
int32_t OleFile :: get_file_offset(const uint8_t* data, uint32_t data_len)
{
    if (searcher == nullptr)
    {
        VBA_DEBUG(vba_data_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL, CURRENT_PACKET,
            "Error in the searcher.\n");
        return -1;
    }

    int32_t offset = searcher->search(search_handle, data, data_len);
    return offset;
}

int32_t cli_readn(const uint8_t*& fd, uint32_t& data_len, void* buff, int32_t count)
{
    int32_t i;

    for (i = 0; i < count; i++)
    {
        if (data_len)
        {
            *((uint8_t*)buff + i) = *(fd + i);
            data_len -= 1;
        }
        else
        {
            break;
        }
    }

    fd += i;
    return i;
}

// Function for RLE decompression.
//
// Run-length encoding (RLE) is a very simple form of data compression
// in which a stream of data is given as the input (i.e. "AAABBCCCC") and
// the output is a sequence of counts of consecutive data values in a row
// (i.e. "3A2B4C"). This type of data compression is lossless, meaning that
// when decompressed, all of the original data will be recovered when decoded.
void OleFile :: decompression(const uint8_t* data, uint32_t& data_len, uint8_t*& local_vba_buffer,
    uint32_t& vba_buffer_offset)
{
    if (!data)
        return;

    if (*data!= SIG_COMP_CONTAINER)
    {
        VBA_DEBUG(vba_data_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL, CURRENT_PACKET,
            "Invalid Compressed flag.\n");
        return;
    }

    int16_t data_header = LETOHS_UNALIGNED(data + 1);

    bool flagCompressed = 0 != (data_header & 0x8000);

    if (((data_header >> 12) & 0x07) != 0b011)
    {
        VBA_DEBUG(vba_data_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL, CURRENT_PACKET,
            "Invalid Chunk signature.\n");
    }

    data += 3;
    data_len -= 3;

    unsigned char buffer[VBA_COMPRESSION_WINDOW]={ };
    if (flagCompressed == 0)
    {
        memcpy(&buffer, data, data_len);
        return;
    }

    unsigned pos = 0;
    bool clean = true;
    uint32_t size = data_len;
    uint8_t flag;
    while (cli_readn(data, size, &flag, 1))
    {
        for (unsigned mask = 1; mask < 0x100; mask <<= 1)
        {
            unsigned int winpos = pos % VBA_COMPRESSION_WINDOW;
            if (flag & mask)
            {
                uint16_t token;
                if (!cli_readn(data, size, &token, 2))
                    return;

                unsigned shift = 12 - (winpos > 0x10) - (winpos > 0x20) - (winpos > 0x40) - (winpos >
                    0x80) - (winpos > 0x100) - (winpos > 0x200) - (winpos > 0x400) - (winpos >
                    0x800);
                uint16_t len = (uint16_t)((token & ((1 << shift) - 1)) + 3);
                unsigned distance = token >> shift;

                uint32_t srcpos = pos - distance - 1;
                if ((((srcpos + len) % VBA_COMPRESSION_WINDOW) < winpos)and
                        ((winpos + len) < VBA_COMPRESSION_WINDOW) and
                        (((srcpos % VBA_COMPRESSION_WINDOW) + len) < VBA_COMPRESSION_WINDOW) and
                        (len <= VBA_COMPRESSION_WINDOW))
                {
                    srcpos %= VBA_COMPRESSION_WINDOW;
                    memcpy(&buffer[winpos], &buffer[srcpos],
                        len);
                    pos += len;
                }
                else
                    while (len-- > 0)
                    {
                        srcpos = (pos - distance - 1) % VBA_COMPRESSION_WINDOW;
                        buffer[pos++ % VBA_COMPRESSION_WINDOW] = buffer[srcpos];
                    }
            }
            else
            {
                if ((pos != 0)and (winpos == 0) and clean)
                {
                    uint16_t token;
                    if (cli_readn(data, size, &token, 2) != 2)
                    {
                        return;
                    }
                    clean = false;
                    break;
                }
                if (cli_readn(data, size,  &buffer[winpos], 1) == 1)
                    pos++;
            }
            clean = true;
        }
    }

    int32_t decomp_len = strlen((char*)buffer);

    if ((vba_buffer_offset + decomp_len) > MAX_VBA_BUFFER_LEN)
    {
        decomp_len =  MAX_VBA_BUFFER_LEN - vba_buffer_offset;
    }
    memcpy((local_vba_buffer + vba_buffer_offset), buffer, decomp_len);
    vba_buffer_offset += decomp_len;
}

// Function to extract the VBA data and send it for RLE decompression.
void OleFile :: find_and_extract_vba(uint8_t*& vba_buf, uint32_t& vba_buf_len)
{
    std::unordered_map<char*, FileProperty*>::iterator it = dir_list->oleentry.begin();
    uint32_t vba_buffer_offset = 0;
    vba_buf = new uint8_t[MAX_VBA_BUFFER_LEN + 1]();

    while (it != dir_list->oleentry.end())
    {
        FileProperty* node = it->second;
        ++it;
        if (node->get_file_type() == STREAM)
        {
            uint8_t* data = nullptr;
            uint32_t data_len;
            get_file_data(node->get_name(), data, data_len);
            uint8_t* data1 = data;
            int32_t offset = get_file_offset(data, data_len);
            if (offset <= 0)
            {
                VBA_DEBUG(vba_data_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL,
                    CURRENT_PACKET,
                    "Stream %s of size %ld does not have VBA code within first detected"
                    " %d bytes\n", node->get_name(), node->get_stream_size(), data_len);
                delete[] data1;
                continue;
            }

            data += offset - 4;
            data_len = data_len - offset + 4;
            VBA_DEBUG(vba_data_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL,
                CURRENT_PACKET, "Stream %s of size %ld has vba code starting at "
                "offset %d bytes. First %d bytes will be processed\n",
                node->get_name(), node->get_stream_size(), (offset - 4), data_len);

            decompression(data, data_len, vba_buf, vba_buffer_offset);
            delete[] data1;
            if ( vba_buffer_offset >= MAX_VBA_BUFFER_LEN)
                break;
        }
    }
    vba_buf_len = vba_buffer_offset;

    //Delete vba_buf if decompression could not happen
    if (!vba_buf_len)
        delete[] vba_buf;
}

// Beginning function of ole file processing.
//
// An OLE file contains streams of data that look like files embedded within the
// OLE file.It can also contain storages, which is a folder that contains streams
// or other storages.
//
// Ole file processing begins with OLE header matching, followed by populating
// the FAT array-list which contains the mapping between current fat sector and
// its next fat sector.Followed by populating the mini-FAT array-list which
// contains the mapping between current mini-fat sector and its next mini-fat
// sector. Followed by reading the entries of all the directory entry arrays of
// an ole file and creating a mapping between the storage/stream name and the
// fileproperty object.Afterwards, based on the directory the data is fetched and
// extracted & RLE decompression is done.
void oleprocess(const uint8_t* const ole_file, const uint32_t ole_length, uint8_t*& vba_buf,
    uint32_t& vba_buf_len)
{
    if (ole_length < OLE_HEADER_LEN)
    {
        VBA_DEBUG(vba_data_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL, CURRENT_PACKET,
            "OLE file data is too short for the inspection. Returning\n");
        return;
    }

    std::unique_ptr<OleFile> olefile (new OleFile(ole_file,ole_length));

    if (!olefile->parse_ole_header())
        return;

    olefile->populate_fat_list();
    olefile->populate_mini_fat_list();
    olefile->walk_directory_list();
    olefile->find_and_extract_vba(vba_buf, vba_buf_len);
}

