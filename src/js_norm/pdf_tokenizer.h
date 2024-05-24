//--------------------------------------------------------------------------
// Copyright (C) 2022-2024 Cisco and/or its affiliates. All rights reserved.
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
// pdf_tokenizer.h author Cisco

#ifndef PDF_TOKENIZER_H
#define PDF_TOKENIZER_H

#include <cstring>
#include <sstream>
#include <unordered_set>

#include "main/snort_types.h"

#define PDFTOKENIZER_NAME_MAX_SIZE 16

namespace jsn
{

class SO_PUBLIC PDFTokenizer : public yyFlexLexer
{
public:
    enum PDFRet
    {
        EOS = 0,
        NOT_NAME_IN_DICTIONARY_KEY,
        INCOMPLETE_ARRAY_IN_DICTIONARY,
        STREAM_NO_LENGTH,
        UNEXPECTED_SYMBOL,
        TOKEN_TOO_LONG,
        MAX
    };

    PDFTokenizer() = delete;
    explicit PDFTokenizer(std::istream& in, std::ostream& out);
    ~PDFTokenizer() override;

    PDFRet process();

private:
    int yylex() override;

    PDFRet h_dict_open();
    PDFRet h_dict_close();
    PDFRet h_dict_name();
    PDFRet h_dict_other();
    inline bool h_lit_str();
    inline bool h_hex_str();
    inline bool h_lit_open();
    inline bool h_lit_close();
    PDFRet h_lit_unescape();
    PDFRet h_lit_oct2chr();
    PDFRet h_hex_hex2chr();
    PDFRet h_hex_hex2chr_u16();
    PDFRet h_lit_u16();
    PDFRet h_lit_u16_unescape();
    PDFRet h_stream_open();
    PDFRet h_stream();
    bool h_stream_close();
    void h_stream_length();
    void h_ref();
    void h_ind_obj_open();
    inline void h_ind_obj_close();
    void h_u16_start();
    void h_u16_break();
    void h_u16_hex_start();
    void h_u16_hex_break();

    PDFRet u16_eval(uint8_t byte);
    void u16_to_u8(uint32_t code);

    struct ObjectString
    {
        void clear()
        { parenthesis_level = 0; }

        int parenthesis_level = 0;
    };

    struct ObjectArray
    {
        void clear()
        { nesting_level = 0; }

        int nesting_level = 0;
    };

    struct ObjectDictionary
    {
        void clear()
        { key_value = true; array_level = 0; }

        bool key_value = true;
        int array_level = 0;
    };

    struct DictionaryEntry
    {
        void clear()
        { key[0] = '\0'; }

        char key[PDFTOKENIZER_NAME_MAX_SIZE] = {0};
    };

    struct Stream
    {
        int rem_length = -1;
        bool is_js = false;
    };

    ObjectString obj_string;
    ObjectArray obj_array;
    ObjectDictionary obj_dictionary;
    DictionaryEntry obj_entry;
    Stream obj_stream;
    std::unordered_set<unsigned int> js_stream_refs;

    // represents UTF-16BE code point
    struct
    {
        uint16_t high = 0;
        uint16_t low = 0;
        int cur_byte = 0;
    } u16_state;
};

bool PDFTokenizer::h_lit_str()
{
    return obj_dictionary.array_level == obj_array.nesting_level and !strcmp(obj_entry.key, "/JS");
}

bool PDFTokenizer::h_hex_str()
{
    return obj_dictionary.array_level == obj_array.nesting_level and !strcmp(obj_entry.key, "/JS");
}

bool PDFTokenizer::h_lit_open()
{
    return ++obj_string.parenthesis_level == 1;
}

bool PDFTokenizer::h_lit_close()
{
    return --obj_string.parenthesis_level == 0;
}

void PDFTokenizer::h_ind_obj_close()
{
    obj_stream.is_js = false;
}

}

#endif
