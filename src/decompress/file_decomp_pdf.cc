//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

// file_decomp_pdf.cc author Ed Borgoyn <eborgoyn@sourcefire.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "file_decomp_pdf.h"

#include <cassert>

#include "main/thread.h"
#include "utils/util.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;

/* Define characters and tokens in PDF grammar */
#define TOK_STRM_OPEN      "stream"
#define TOK_STRM_CLOSE     "endstream"

#define TOK_OBJ_OPEN       "obj"
#define TOK_OBJ_CLOSE      "endobj"

#define TOK_DICT_OPEN      "<<"
#define TOK_DICT_CLOSE     ">>"
#define TOK_DICT_FILT      "Filter"
#define TOK_DICT_FLATE     "FlateDecode"
#define TOK_DICT_FLATE_ALT "Fl"
#define TOK_DICT_PARMS     "DecodeParms"
#define TOK_DICT_PARMS_ALT "DP"
#define TOK_DICT_LENGTH    "Length"
#define TOK_DICT_NULL      "null"
#define TOK_DICT_NULL_FILT " null "  // Enclose the null object in spaces
#define TOK_XRF_XREF       "xref"
//#define TOK_XRF_TRAILER    "trailer"  // unused
#define TOK_XRF_STARTXREF  "startxref"
#define TOK_XRF_END        "%%EOF"

#define WHITESPACE_STRING  "\011\012\014\015\040" // plus \000

#define TOK_EOL_CR         "\r"
#define TOK_EOL_LF         "\n"
#define TOK_EOL_CRLF       "\r\n"

#define CHR_CR             '\r'
#define CHR_LF             '\n'

#define CHR_COMMENT        '%'

#define CHR_ARRAY_OPEN     '['
#define CHR_ARRAY_CLOSE    ']'

#define CHR_ANGLE_OPEN     '<'
#define CHR_ANGLE_CLOSE    '>'

#define CHR_SPACE          ' '
#define CHR_NAME_SEP       '/'

#define IS_WHITESPACE(c) ((strchr((const char*)WHITESPACE_STRING, (int)(c)) != nullptr) || ((c) == 0))
#define IS_EOL(c) (((c) == CHR_CR) || ((c) == CHR_LF))

/* Define the parser states */
typedef enum p_states
{
    P_START = 1,    // Ground state, nothing 'open'
    P_COMMENT,      // inside a comment (initial state of parser)
    P_IND_OBJ,      // Indirect Object - Sub_State usage
    P_XREF,         // The combined xref, trailer, startxref top level items
    P_DICT_OBJECT,  // A dictionary object
    P_STREAM        // A pseudo state used to process a stream object
} p_state_t;

typedef enum p_xref_substates
{
    P_XREF_TOKEN = 1,
    P_XREF_END_TOKEN
} p_xref_t;

typedef enum p_dict_substates
{
    P_DICT_OPEN = 1,
    P_DICT_OPEN_TOK,
    P_DICT_CLOSE_TOK,
    P_DICT_FILTER,
    P_DICT_SKIP,
    P_DICT_ACTIVE
} p_dict_t;

typedef enum p_indirect_object_substates
{
    P_OBJ_NUMBER = 1,
    P_GEN_NUMBER,
    P_OBJ_TOKEN,
    P_OBJ_EOL,
    P_STREAM_TOKEN,
    P_STREAM_EOL,
    P_STREAM_LF,
    P_ENDSTREAM_TOKEN,
    P_ENDOBJ_TOKEN
} p_indirect_object_substate_t;

static struct filters_s
{
    const char* Token;
    uint8_t Length;
    uint8_t Type;
} Filter_Map[] =
{
    { TOK_DICT_FLATE, (sizeof(TOK_DICT_FLATE)-1), FILE_COMPRESSION_TYPE_DEFLATE },
    { TOK_DICT_FLATE_ALT, (sizeof(TOK_DICT_FLATE_ALT)-1), FILE_COMPRESSION_TYPE_DEFLATE },
    { TOK_DICT_NULL, (sizeof(TOK_DICT_NULL)-1), FILE_COMPRESSION_TYPE_NONE },
    { nullptr, 0, FILE_COMPRESSION_TYPE_NONE }
};

/* Given a pointer to a /Filter value token, return the
   associated compression type from the Filter_Map. */
static inline uint8_t Get_Decomp_Type(uint8_t* Token, uint8_t Length)
{
    int Index;

    Index=0;

    while ( Filter_Map[Index].Token != nullptr )
    {
        if ( (Filter_Map[Index].Length == Length) &&
            (strncmp( (const char*)Token, Filter_Map[Index].Token, Length) == 0 ) )
            return( Filter_Map[Index].Type );
        else
            Index += 1;
    }
    return( FILE_COMPRESSION_TYPE_NONE );
}

static inline void Process_One_Filter(fd_session_t* SessionPtr, uint8_t* Token, uint8_t Length)
{
    uint8_t Comp_Type;

    /* Lookup the token and see if it matches a known filter */
    Comp_Type = Get_Decomp_Type(Token, Length);

    if ( Comp_Type != FILE_COMPRESSION_TYPE_NONE )
    {
        /* Check if we've found one already.  Indicate cascading if we did. */
        if ( SessionPtr->Decomp_Type != FILE_COMPRESSION_TYPE_NONE )
        {
            File_Decomp_Alert(SessionPtr, FILE_DECOMP_ERR_PDF_CASC_COMP);
            SessionPtr->Decomp_Type = FILE_COMPRESSION_TYPE_NONE;
        }
        else
        {
            /* Found our first matching, supported filter type */
            SessionPtr->Decomp_Type = Comp_Type;
            SessionPtr->PDF->Decomp_Type = Comp_Type;
        }
    }
    else
    {
        File_Decomp_Alert(SessionPtr, FILE_DECOMP_ERR_PDF_UNSUP_COMP_TYPE);
        SessionPtr->Decomp_Type = FILE_COMPRESSION_TYPE_NONE;
    }
}

/* Parse the buffered Filter_Spec and create a stream decompression
   mode and/or event alerts.  Return File_Decomp_OK if successful.
   Return File_Decomp_Error for a parsing error. */
static fd_status_t Process_Filter_Spec(fd_session_t* SessionPtr)
{
    /* The following string contains CHR_ARRAY_OPEN, CHR_ARRAY_CLOSE,
       and CHR_NAME_SEP. */
    const uint8_t Delim_Str[] = { "\011\012\014\015\040/[]" };
    bool Found_Array = false;
    bool Found_Token = false;
    uint8_t* Filter;
    uint8_t Length;
    int Index;

    fd_status_t Ret_Code = File_Decomp_OK;
    fd_PDF_Parse_p_t p = &(SessionPtr->PDF->Parse);

    /* Assume the 'no compression' result */
    SessionPtr->Decomp_Type = FILE_COMPRESSION_TYPE_NONE;
    Filter = nullptr;
    Length = 0;

    for ( Index=0; Index<p->Filter_Spec_Index; Index++ )
    {
        const uint8_t c = p->Filter_Spec_Buf[Index];

        if ( (c == 0) || (strchr( (const char*)Delim_Str, (int)c) != nullptr) )
        {
            if ( c == CHR_ARRAY_OPEN )
            {
                /* Looks like an array starting, but we are already
                   in an array, or have seen a filter spec already.  */
                if ( Found_Array || Found_Token || (Filter != nullptr) )
                {
                    Ret_Code = File_Decomp_Error;
                    break;
                }
                else
                {
                    Found_Array = true;
                    Filter = nullptr;
                    Length = 0;
                    continue;  // Nothing else to do, goto next char
                }
            }
            else if ( c == CHR_ARRAY_CLOSE )
            {
                /* We MUST have an array open at this point. */
                if ( !Found_Array )
                {
                    Ret_Code = File_Decomp_Error;
                    break;
                }
                Found_Array = false;
            }

            /* The white-space or other separator terminates the
               current filter name we are parsing. */
            if ( (Filter != nullptr) && (Length > 0) )
            {
                Process_One_Filter(SessionPtr, Filter, Length);
                Filter = nullptr;
                Length = 0;
            }
        }
        else  // non-separator character
        {
            /* Start a token if we haven't already. */
            if ( Filter == nullptr )
            {
                Found_Token = true;  // Used in the array syntax checking
                Filter = &(p->Filter_Spec_Buf[Index]);
                Length = 1;  // We've found one character so far
            }
            else
            {
                Length += 1;
            }
        }
    }

    /* Indicate an error is we exit the parsing with the array open */
    if ( Found_Array )
        Ret_Code = File_Decomp_Error;

    /* Any error code implies no compression type */
    if ( Ret_Code == File_Decomp_Error )
        SessionPtr->Decomp_Type = FILE_COMPRESSION_TYPE_NONE;
    /* Look for case where the filter name ends at the
       last character of the filter_spec. */
    else if ( (Filter != nullptr) && (Length > 0) )
        Process_One_Filter(SessionPtr, Filter, Length);

    return( Ret_Code );
}

static inline void Init_Parser(fd_session_t* SessionPtr)
{
    fd_PDF_Parse_p_t p = &(SessionPtr->PDF->Parse);
    /* The parser starts in the P_COMMENT state we start
       parsing the file just after the signature is located
       and the signature is syntactically a comment. */
    p->State = P_COMMENT;
    p->Parse_Stack_Index = 0; // Stack is empty
    p->xref_tok = (const uint8_t*)TOK_XRF_STARTXREF;
}

static inline fd_status_t Push_State(fd_PDF_Parse_p_t p)
{
    fd_PDF_Parse_Stack_p_t StckPtr;

    if ( p->Parse_Stack_Index >= (PARSE_STACK_LEN-1) )
        return( File_Decomp_Error );

    StckPtr = &(p->Parse_Stack[(p->Parse_Stack_Index)++]);

    StckPtr->State = p->State;
    StckPtr->Sub_State = p->Sub_State;

    return( File_Decomp_OK );
}

static inline fd_status_t Pop_State(fd_PDF_Parse_p_t p)
{
    fd_PDF_Parse_Stack_p_t StckPtr;

    if ( p->Parse_Stack_Index == 0 )
        return( File_Decomp_Error );

    StckPtr = &(p->Parse_Stack[--(p->Parse_Stack_Index)]);

    p->Elem_Index = 0;  // Reset to beginning of token as can't push/pop in mid-token
    p->State = StckPtr->State;
    p->Sub_State = StckPtr->Sub_State;

    return( File_Decomp_OK );
}

/* If there's a previous state on the stack, return a pointer to it, else return NULL */
static inline fd_PDF_Parse_Stack_p_t Get_Previous_State(fd_PDF_Parse_p_t p)
{
    if ( p->Parse_Stack_Index == 0 )
        return( (fd_PDF_Parse_Stack_p_t)nullptr );

    return( &(p->Parse_Stack[(p->Parse_Stack_Index)-1]) );
}

/* Objects are the heart and soul of the PDF.  In particular, we need to concentrate on Dictionary
   objects and objects that map to the Filter element in Dictionaries.  'null' is a valid object'.
   Objects can be recursively composed of arrays of objects. In our limited parsing paradigm, we
   will only process the contents of top level Dictionaries and ignore deeper levels.  We will
   only explore Dictionary objects within Indirect Objects.  */
static inline fd_status_t Handle_State_DICT_OBJECT(fd_session_t* SessionPtr, uint8_t c)
{
    fd_PDF_Parse_p_t p = &(SessionPtr->PDF->Parse);

    /* enter with c being an EOL from the ind obj state */
    if ( p->State != P_DICT_OBJECT )
    {
        p->Sub_State = P_DICT_OPEN;  // Looking to open a Dict`
        p->Dict_Nesting_Cnt = 0;  // No Dicts are 'active'
        p->State = P_DICT_OBJECT;
        p->Filter_Spec_Index = 0;
        SessionPtr->Decomp_Type = FILE_COMPRESSION_TYPE_NONE;
        return( File_Decomp_OK );
    }

    switch ( p->Sub_State )
    {
    /* look for the first angle bracket */
    case ( P_DICT_OPEN ):
    {
        if ( c == CHR_ANGLE_OPEN )
        {
            p->Sub_State = P_DICT_OPEN_TOK;
        }
        else if ( !IS_WHITESPACE(c) )
        {
            /* for other objects, just skip and wait for the close of the
               indirect object as we don't parse objects other than Dict's. */
            if ( Pop_State(p) == File_Decomp_Error )
                return( File_Decomp_Error );
        }
        break;
    }
    /* now look for the second angle bracket */
    case ( P_DICT_OPEN_TOK ):
    {
        if ( c == CHR_ANGLE_OPEN )
        {
            /* Only ACTIVE if this is the opening of the
               'base level' Dict, NOT a nested one. */
            if ( p->Dict_Nesting_Cnt++ == 0 )
            {
                p->Sub_State = P_DICT_ACTIVE;
            }
            else
            {
                p->Sub_State = P_DICT_SKIP;
            }
        }
        else
        {
            /* for other objects, just skip and wait for the close of the
               indirect object as we don't parse objects other than Dict's. */
            if ( Pop_State(p) == File_Decomp_Error )
                return( File_Decomp_Error );
        }
        break;
    }

    case ( P_DICT_SKIP ):
    case ( P_DICT_ACTIVE ):
    {
        /* Main purpose is to search for the value portion of the
           /Filter entry.  Main loop looks for the /Filter token
           and handles other diversion such as nested Dict objects.
           If the /Filter token doesn't exist then we don't fill the
           Filter_Spec_Buf[].  If in skip mode, no need to look for token. */
        char Filter_Tok[] = TOK_DICT_FILT;

        if ( (p->Sub_State == P_DICT_ACTIVE) && c == Filter_Tok[p->Elem_Index++] )
        {
            if ( Filter_Tok[p->Elem_Index] == '\0' )
            {
                p->Sub_State = P_DICT_FILTER;
            }
        }
        else
        {
            /* On a mis-match, reset back to the start of the token */
            p->Elem_Index = 0;

            /* we might find a Sub-Dict while we're looking */
            if ( c == CHR_ANGLE_OPEN )
            {
                /* Save where we are, and process the Dict */
                if ( Push_State(p) != File_Decomp_OK )
                    return( File_Decomp_Error );
                p->Sub_State = P_DICT_OPEN_TOK;
            }
            else if ( c == CHR_ANGLE_CLOSE )
            {
                if ( Push_State(p) != File_Decomp_OK )
                    return( File_Decomp_Error );
                p->Sub_State = P_DICT_CLOSE_TOK;
            }
        }
        break;
    }

    case ( P_DICT_FILTER ):
    {
        if ( (c == CHR_ANGLE_CLOSE) ||
            ((c == CHR_NAME_SEP) && (p->Dict_Nesting_Cnt==3) ))      //  See the large comment
                                                                     // below
        {
            if ( c == CHR_ANGLE_CLOSE )
            {
                if ( Push_State(p) != File_Decomp_OK )
                    return( File_Decomp_Error );
                p->Sub_State = P_DICT_CLOSE_TOK;
            }
            else
            {
                p->Sub_State = P_DICT_SKIP;
            }
            if ( (Process_Filter_Spec(SessionPtr)  == File_Decomp_Error) )
                return( File_Decomp_Error );
        }
        else
        {
            /* Since we don't have a full object parse, we need to assure
               that we capture the entire filter spec string.  The '>' is always
               a terminator, but we also want to terminate on the next /Name entry
               after a possible array of /Names.  The Dict_Nesting_Cnt is used to
               step through the transition options.  The '/' character is only a valid
               filter spec terminator if we've seen a valid array or one /Name entry. */
            if ( (c == CHR_NAME_SEP) && (p->Dict_Nesting_Cnt==1) )
                p->Dict_Nesting_Cnt = 3;
            else if ( (c == CHR_ARRAY_OPEN) && (p->Dict_Nesting_Cnt==1) )
                p->Dict_Nesting_Cnt = 2;
            else if ( (c == CHR_ARRAY_CLOSE) && (p->Dict_Nesting_Cnt==2) )
                p->Dict_Nesting_Cnt = 3;

            if ( p->Filter_Spec_Index < (FILTER_SPEC_BUF_LEN-1) )
            {
                p->Filter_Spec_Buf[p->Filter_Spec_Index++] = c;
            }
            else
                return( File_Decomp_Error );
        }
        break;
    }

    case ( P_DICT_CLOSE_TOK ):
    {
        if ( c == CHR_ANGLE_CLOSE )
        {
            /*  Pop the temp state just prior to the first > */
            if ( Pop_State(p) == File_Decomp_Error )
                return( File_Decomp_Error );

            /* Pop back to the state before the <<.  */
            /* But not so fast...  Look at what state/sub-state we are popping
               back to.  If it's IND_OBJ, AND we have an active filter type,
               we don't want to scan to the end of the stream but rather the beginning
               of the stream.  */
            if ( SessionPtr->Decomp_Type != FILE_COMPRESSION_TYPE_NONE )
            {
                fd_PDF_Parse_Stack_p_t StckPtr;

                if ( (StckPtr = Get_Previous_State(p)) == nullptr )
                {
                    /* There MUST be a previous state that got us here. */
                    return( File_Decomp_Error );
                }
                else
                {
                    if ( (StckPtr->State == P_IND_OBJ) &&
                        (StckPtr->Sub_State == P_ENDOBJ_TOKEN) )
                    {
                        StckPtr->Sub_State = P_STREAM_TOKEN;
                    }
                }
            }
            if ( Pop_State(p) == File_Decomp_Error )
                return( File_Decomp_Error );
        }
        else
        /* Return to where we looking (didn't get >>) */
        if ( Pop_State(p) == File_Decomp_Error )
            return( File_Decomp_Error );
        break;
    }

    default:
        return( File_Decomp_Error );
    }

    return( File_Decomp_OK );
}

static inline fd_status_t Process_Stream(fd_PDF_Parse_p_t p)
{
    p->Sub_State = P_ENDSTREAM_TOKEN;
    p->State = P_IND_OBJ;

    if ( Push_State(p) == File_Decomp_Error )
        return( File_Decomp_Error );
    else
    {
        p->State = P_STREAM;
        p->Sub_State = 0;
    }
    return( File_Decomp_OK );
}

/* Indirect Objects occur only at the top level of the file and comprise the
   bulk of the file content. */
static inline fd_status_t Handle_State_IND_OBJ(fd_session_t* SessionPtr, uint8_t c)
{
    fd_PDF_Parse_p_t p = &(SessionPtr->PDF->Parse);

    /* Upon initial entry, setup state context */
    if ( p->State != P_IND_OBJ )
    {
        p->State = P_IND_OBJ;
        p->Sub_State = P_OBJ_NUMBER;
        p->Elem_Index = 1;
        p->Elem_Buf[0] = c;
        return( File_Decomp_OK );
    }

    switch ( p->Sub_State )
    {
    case ( P_OBJ_NUMBER ):
    case ( P_GEN_NUMBER ):
    {
        if ( isdigit(c) )
        {
            if ( p->Elem_Index < (sizeof(p->Elem_Buf)-1))
            {
                p->Elem_Buf[p->Elem_Index++] = c;
            }
            else
                return( File_Decomp_Error );
        }
        else if ( c == CHR_SPACE )
        {
            uint32_t Value;
            p->Elem_Buf[p->Elem_Index] = '\0';
            Value = (uint32_t)strtoul( (const char*)p->Elem_Buf, nullptr, 10);
            if ( p->Sub_State == P_OBJ_NUMBER )
            {
                p->Obj_Number = Value;
                p->Sub_State = P_GEN_NUMBER;
                p->Elem_Index = 0;
            }
            else
            {
                p->Gen_Number = Value;
                p->Sub_State = P_OBJ_TOKEN;
                p->Elem_Index = 0;
            }
        }
        break;
    }

    case ( P_OBJ_TOKEN ):
    {
        if ( c == TOK_OBJ_OPEN[p->Elem_Index++] )
        {
            if ( TOK_OBJ_OPEN[p->Elem_Index] == '\0' )
            {
                p->Sub_State = P_OBJ_EOL;
                break;
            }
        }
        else
        {
            return( File_Decomp_Error );
        }
    }
    // fallthrough

    case ( P_OBJ_EOL ):
    {
        if ( IS_EOL(c) )
        {
            p->Sub_State = P_ENDOBJ_TOKEN;
            /* Save our place in the IND_OBJ and go process an OBJECT */
            if ( Push_State(p) != File_Decomp_OK )
                return( File_Decomp_Error );
            return( Handle_State_DICT_OBJECT(SessionPtr, c) );
        }

        break;
    }

    case ( P_STREAM_TOKEN ):
    {
        if ( c == TOK_STRM_OPEN[p->Elem_Index++] )
        {
            if ( TOK_STRM_OPEN[p->Elem_Index] == '\0' )
            {
                /* Look for the limited EOL sequence */
                p->Sub_State = P_STREAM_EOL;
            }
            break;
        }
        else if ( IS_WHITESPACE(c) )
        {
            p->Elem_Index = 0;      // reset and keep looking
        }
        else
            return( File_Decomp_Error );

        break;
    }

    case ( P_STREAM_EOL ):
    {
        if ( c == CHR_CR )
        {
            /* The next char MUST be a LF or error */
            p->Sub_State = P_STREAM_LF;
        }
        else if ( c == CHR_LF )
        {
            if ( Process_Stream(p) != File_Decomp_OK )
                return( File_Decomp_Error );
        }
        else
            return( File_Decomp_Error );

        break;
    }

    case ( P_STREAM_LF ):
    {
        if ( c == CHR_LF )
        {
            if ( Process_Stream(p) != File_Decomp_OK )
                return( File_Decomp_Error );
        }
        else
            return( File_Decomp_Error );
        break;
    }

    case ( P_ENDSTREAM_TOKEN ):
    {
        if ( c == TOK_STRM_CLOSE[p->Elem_Index++] )
        {
            if ( TOK_STRM_CLOSE[p->Elem_Index] == '\0' )
            {
                p->Sub_State = P_ENDOBJ_TOKEN;
                p->Elem_Index = 0;  // reset for P_ENDOBJ_TOKEN to use
            }
        }
        else
        {
            p->Elem_Index = 0;      // reset and keep looking
        }

        break;
    }

    case ( P_ENDOBJ_TOKEN ):
    {
        if ( c == TOK_OBJ_CLOSE[p->Elem_Index++] )
        {
            if ( TOK_OBJ_CLOSE[p->Elem_Index] == '\0' )
            {
                /* we found the end of the indirect object, return
                   back to the parent state (always START in this case) */
                return( Pop_State(p) );
            }
        }
        else
        {
            /* Since we don't necessarily handle all object types correctly,
               we will spin here searching for the end token.  Not the best,
               but should work if we don't have a full object parser. */
            p->Elem_Index = 0;      // reset and keep looking
        }

        break;
    }

    default:
        return( File_Decomp_Error );
    }

    return( File_Decomp_OK );
}

/* A simple state machine to process the xref/trailer/startxref file segments.  No
   semantic processing and only rough syntactical processing to allow us to skip through
   this segment. */
static inline fd_status_t Handle_State_XREF(fd_session_t* SessionPtr, uint8_t c)
{
    fd_PDF_Parse_p_t p = &(SessionPtr->PDF->Parse);

    if ( p->State != P_XREF )
    {
        p->Sub_State = P_XREF_TOKEN;
        p->Elem_Index = 1;  // already matched the first char in START state
        p->State = P_XREF;
        p->xref_tok = (const uint8_t*)((c == TOK_XRF_XREF[0]) ? TOK_XRF_XREF : TOK_XRF_STARTXREF);
        return( File_Decomp_OK );
    }

    switch ( p->Sub_State )
    {
    case ( P_XREF_TOKEN ):
    {
        if ( c == p->xref_tok[p->Elem_Index++] )
        {
            if ( p->xref_tok[p->Elem_Index] == '\0' )
            {
                p->Elem_Index = 0;
                p->Sub_State = P_XREF_END_TOKEN;
            }
        }
        else
        {
            return( File_Decomp_Error );
        }
        break;
    }

    case ( P_XREF_END_TOKEN ):
    {
        if ( c == TOK_XRF_END[p->Elem_Index++] )
        {
            if ( TOK_XRF_END[p->Elem_Index] == '\0' )
            {
                p->State = P_START;
            }
        }
        else
        {
            /* Since we don't necessarily handle all xref content correctly,
               we will spin here searching for the end token.  Not the best,
               but should work if we don't have a full object parser. */
            p->Elem_Index = 0;      // reset and keep looking
        }

        break;
    }

    default:
        return( File_Decomp_Error );
    }

    return( File_Decomp_OK );
}

static inline fd_status_t Handle_State_START(fd_session_t* SessionPtr, uint8_t c)
{
    fd_PDF_Parse_p_t p = &(SessionPtr->PDF->Parse);
    /* Skip any whitespace.  This will include
       the LF as part of a <CRLF> EOL token. */
    if ( IS_WHITESPACE(c) )
    {
        return( File_Decomp_OK );
    }
    if ( c == CHR_COMMENT )
    {
        p->State = P_COMMENT;
    }
    else if ( isdigit(c) )
    {
        /* Save state and process an indirect object */
        if ( Push_State(p) != File_Decomp_OK )
            return( File_Decomp_Error );
        return( Handle_State_IND_OBJ(SessionPtr, c) );
    }
    else if ( (c == TOK_XRF_XREF[0]) || (c == TOK_XRF_STARTXREF[0]) )
    {
        /* Save state and process the xref block */
        if ( Push_State(p) != File_Decomp_OK )
            return( File_Decomp_Error );
        return( Handle_State_XREF(SessionPtr, c) );
    }
    else if ( !(IS_WHITESPACE(c)) )
    {
        /* If is not an ind_obj started, or a comment starting, then
           we don't know what it is, so return an error. */
        return( File_Decomp_Error );
    }

    return( File_Decomp_OK );
}

/* Incrementally search the incoming data for a PDF compressed stream
   (of the type that we can decompress).  Move bytes to outgoing data
   up to the beginning of the compressed segment. */
// FIXIT-L Should remove the /Filter spec that was located by replacing the name with null.

/* Parse file until input blocked or stream located. */
static fd_status_t Locate_Stream_Beginning(fd_session_t* SessionPtr)
{
    fd_PDF_Parse_p_t p = &(SessionPtr->PDF->Parse);
    fd_status_t Ret_Code = File_Decomp_OK;

    while ( true )
    {
        /* No reason to parse if there's no input or
           room for output. */
        if ( SessionPtr->Avail_In == 0 )
            return( File_Decomp_BlockIn );
        if ( SessionPtr->Avail_Out == 0 )
            return( File_Decomp_BlockOut );

        /* Get next byte in input queue */
        uint8_t c = *SessionPtr->Next_In;

        switch ( p->State )
        {
        /* The 'ground' state of the parser. All indirect objects
           should be located at this level. */
        case ( P_START ):
        {
            if ( (Ret_Code = Handle_State_START(SessionPtr, c)) != File_Decomp_OK )
                return( Ret_Code );
            break;
        }

        case ( P_COMMENT ):
        {
            /* CR or LF closes the comment.  The optional LF
               after a CR will be considered whitespace and
               removed in the P_START state. */
            if ( IS_EOL(c) )
                p->State = P_START;
            break;
        }

        case ( P_IND_OBJ ):
        {
            if ( (Ret_Code = Handle_State_IND_OBJ(SessionPtr, c)) != File_Decomp_OK )
                return( Ret_Code );
            break;
        }

        case ( P_DICT_OBJECT ):
        {
            if ( (Ret_Code = Handle_State_DICT_OBJECT(SessionPtr, c)) != File_Decomp_OK )
                return( Ret_Code );
            break;
        }

        case ( P_XREF ):
        {
            if ( (Ret_Code = Handle_State_XREF(SessionPtr, c)) != File_Decomp_OK )
                return( Ret_Code );
            break;
        }

        case ( P_STREAM ):
        {
            return( File_Decomp_Complete );
        }

        default:
            return( File_Decomp_Error );
        }
        /* After parsing, move the byte from the input to the
           output stream.  We can only be here if there's input
           available and output space. */
        (void)Move_1(SessionPtr);
    }
}

static fd_status_t Init_Stream(fd_session_t* SessionPtr)
{
    fd_PDF_p_t StPtr = SessionPtr->PDF;

    switch ( StPtr->Decomp_Type )
    {
    case FILE_COMPRESSION_TYPE_DEFLATE:
    {
        int z_ret;

        z_stream* z_s = &(StPtr->PDF_Decomp_State.Deflate.StreamDeflate);

        memset( (char*)z_s, 0, sizeof(z_stream));

        z_s->zalloc = (alloc_func)nullptr;
        z_s->zfree = (free_func)nullptr;
        SYNC_IN(z_s)

        z_ret = inflateInit2(z_s, 47);

        if ( z_ret != Z_OK )
        {
            File_Decomp_Alert(SessionPtr, FILE_DECOMP_ERR_PDF_DEFL_FAILURE);
            return( File_Decomp_Error );
        }

        break;
    }
    default:
        return( File_Decomp_Error );
    }

    return( File_Decomp_OK );
}

static fd_status_t Decomp_Stream(fd_session_t* SessionPtr)
{
    fd_PDF_p_t StPtr = SessionPtr->PDF;

    /* No reason to decompress if there's no input or
       room for output. */
    if ( SessionPtr->Avail_In == 0 )
        return( File_Decomp_BlockIn );
    if ( SessionPtr->Avail_Out == 0 )
        return( File_Decomp_BlockOut );

    switch ( StPtr->Decomp_Type )
    {
    case FILE_COMPRESSION_TYPE_DEFLATE:
    {
        int z_ret;
        z_stream* z_s = &(StPtr->PDF_Decomp_State.Deflate.StreamDeflate);

        SYNC_IN(z_s)

        z_ret = inflate(z_s, Z_SYNC_FLUSH);

        SYNC_OUT(z_s)

        if ( z_ret == Z_STREAM_END )
        {
            return( File_Decomp_Complete );
        }

        if ( z_ret != Z_OK )
        {
            File_Decomp_Alert(SessionPtr, FILE_DECOMP_ERR_PDF_DEFL_FAILURE);
            return( File_Decomp_Error );
        }

        break;
    }
    default:
        return( File_Decomp_Error );
    }

    return( File_Decomp_OK );
}

/* After processing a stream, close the decompression engine
   and return the state of the parser. */
static fd_status_t Close_Stream(fd_session_t* SessionPtr)
{
    /* Put the parser state back where it was interrupted */
    if ( Pop_State(&(SessionPtr->PDF->Parse) ) == File_Decomp_Error )
        return( File_Decomp_Error );

    SessionPtr->PDF->State = PDF_STATE_LOCATE_STREAM;

    return( File_Decomp_OK );
}

/* Abort the decompression session upon command from caller. */
fd_status_t File_Decomp_End_PDF(fd_session_t* SessionPtr)
{
    fd_PDF_p_t StPtr;

    if ( SessionPtr == nullptr )
        return( File_Decomp_Error );

    StPtr = SessionPtr->PDF;

    if ( (StPtr->State != PDF_STATE_INIT_STREAM) &&
        (StPtr->State != PDF_STATE_PROCESS_STREAM) )
        return( File_Decomp_OK );

    switch ( StPtr->Decomp_Type )
    {
    case FILE_COMPRESSION_TYPE_DEFLATE:
    {
        int z_ret;
        z_stream* z_s = &(StPtr->PDF_Decomp_State.Deflate.StreamDeflate);

        z_ret = inflateEnd(z_s);

        if ( z_ret != Z_OK )
        {
            File_Decomp_Alert(SessionPtr, FILE_DECOMP_ERR_PDF_DEFL_FAILURE);
            return( File_Decomp_Error );
        }

        break;
    }
    default:
        return( File_Decomp_Error );
    }

    return( File_Decomp_OK );
}

/* From caller, initialize PDF state machine. */
fd_status_t File_Decomp_Init_PDF(fd_session_t* SessionPtr)
{
    if ( SessionPtr == nullptr )
        return( File_Decomp_Error );

    SessionPtr->PDF = (fd_PDF_t*)snort_calloc(sizeof(fd_PDF_t));

    fd_PDF_p_t StPtr = SessionPtr->PDF;

    Init_Parser(SessionPtr);

    StPtr->Decomp_Type = FILE_COMPRESSION_TYPE_NONE;

    /* Search for Dictionary/Stream object. */
    StPtr->State = PDF_STATE_LOCATE_STREAM;

    return( File_Decomp_OK );
}

/* Run the PDF state machine */
fd_status_t File_Decomp_PDF(fd_session_t* SessionPtr)
{
    fd_status_t Ret_Code;

    if ( (SessionPtr == nullptr) || (SessionPtr->File_Type != FILE_TYPE_PDF) )
        return( File_Decomp_Error );

    /* Process all data until blocked */
    while ( true )
    {
        switch ( SessionPtr->PDF->State )
        {
        case ( PDF_STATE_LOCATE_STREAM ):
        {
            /* Will return File_Decomp_Complete if/when the start of a valid compressed
               stream is located.  Decomp_Type will be set. The parsing will be suspended.  */
            if ( (Ret_Code = Locate_Stream_Beginning(SessionPtr) ) == File_Decomp_Error)
            {
                SessionPtr->Error_Event = FILE_DECOMP_ERR_PDF_PARSE_FAILURE;
                return( File_Decomp_DecompError );
            }

            /* If we didn't succeed then get more input */
            if ( Ret_Code != File_Decomp_Complete )
                return( Ret_Code );

            /* The Parsing state remains, we break out to perform the stream
               decompression. */
            if ( SessionPtr->Decomp_Type == FILE_COMPRESSION_TYPE_NONE )
            {
                break;
            }
            else
            {
                SessionPtr->PDF->State = PDF_STATE_INIT_STREAM;
            }
        }
        // fallthrough

        case ( PDF_STATE_INIT_STREAM ):
        {
            /* Initialize the selected decompression engine. */
            Ret_Code = Init_Stream(SessionPtr);
            if ( Ret_Code != File_Decomp_OK )
            {
                File_Decomp_End_PDF(SessionPtr);
                if ( Close_Stream(SessionPtr) != File_Decomp_OK )
                    return( File_Decomp_Error );
                File_Decomp_Alert(SessionPtr, FILE_DECOMP_ERR_PDF_DEFL_FAILURE);
                break;
            }

            SessionPtr->PDF->State = PDF_STATE_PROCESS_STREAM;
        }
        // fallthrough

        case ( PDF_STATE_PROCESS_STREAM ):
        {
            Ret_Code = Decomp_Stream(SessionPtr);
            /* Has the decompressor indicated the end of the data */
            if ( Ret_Code == File_Decomp_Error )
            {
                File_Decomp_End_PDF(SessionPtr);
                if ( Close_Stream(SessionPtr) != File_Decomp_OK )
                    return( File_Decomp_Error );
                File_Decomp_Alert(SessionPtr, FILE_DECOMP_ERR_PDF_DEFL_FAILURE);
                break;
            }
            /* OK -> circle back for more input */
            else if ( Ret_Code == File_Decomp_OK )
                break;
            else if ( Ret_Code != File_Decomp_Complete )
                return( Ret_Code );

            /* Close the decompression engine */
            if ( (Ret_Code = File_Decomp_End_PDF(SessionPtr) ) == File_Decomp_Error)
                return( File_Decomp_Error);

            /* Put the parser state back where it was interrupted */
            if ( (Close_Stream(SessionPtr) ) == File_Decomp_Error )
                return( File_Decomp_Error );

            break;
        }

        default:
            return( File_Decomp_Error );
        } // switch()
    } // while()

    // can not reach this point
    assert(false);
}

//--------------------------------------------------------------------------
// unit tests 
//--------------------------------------------------------------------------

#ifdef UNIT_TEST

TEST_CASE("File_Decomp_PDF-null", "[file_decomp_pdf]")
{
    REQUIRE((File_Decomp_PDF((fd_session_t*)nullptr) == File_Decomp_Error));
}

TEST_CASE("File_Decomp_Init_PDF-null", "[file_decomp_pdf]")
{
    REQUIRE((File_Decomp_Init_PDF((fd_session_t*)nullptr) == File_Decomp_Error));
}

TEST_CASE("File_Decomp_End_PDF-null", "[file_decomp_pdf]")
{
    REQUIRE((File_Decomp_End_PDF((fd_session_t*)nullptr) == File_Decomp_Error));
}

TEST_CASE("File_Decomp_PDF-not_pdf-error", "[file_decomp_pdf]")
{
    fd_session_t* p_s = File_Decomp_New();

    REQUIRE(p_s != nullptr);
    p_s->PDF = (fd_PDF_t*)snort_calloc(sizeof(fd_PDF_t));
    p_s->File_Type = FILE_TYPE_SWF;
    REQUIRE((File_Decomp_PDF(p_s) == File_Decomp_Error));
    p_s->File_Type = FILE_TYPE_PDF;
    File_Decomp_Free(p_s);
}

TEST_CASE("File_Decomp_PDF-bad_state-error", "[file_decomp_pdf]")
{
    fd_session_t* p_s = File_Decomp_New();

    REQUIRE(p_s != nullptr);
    p_s->PDF = (fd_PDF_t*)snort_calloc(sizeof(fd_PDF_t));
    p_s->File_Type = FILE_TYPE_PDF;
    p_s->PDF->State = PDF_STATE_NEW;
    REQUIRE((File_Decomp_PDF(p_s) == File_Decomp_Error));
    File_Decomp_Free(p_s);
}

TEST_CASE("File_Decomp_End_PDF-bad_type-error", "[file_decomp_pdf]")
{
    fd_session_t* p_s = File_Decomp_New();

    REQUIRE(p_s != nullptr);
    p_s->PDF = (fd_PDF_t*)snort_calloc(sizeof(fd_PDF_t));
    p_s->File_Type = FILE_TYPE_PDF;
    p_s->PDF->Decomp_Type = FILE_COMPRESSION_TYPE_LZMA;
    p_s->PDF->State = PDF_STATE_PROCESS_STREAM;
    REQUIRE((File_Decomp_End_PDF(p_s) == File_Decomp_Error));
    File_Decomp_Free(p_s);
}
#endif

