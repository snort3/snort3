/*
** Copyright (C) 2006-2013 Sourcefire, Inc.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

/*
 * Author: Steven Sturges
 * sf_attribute_table_parser.l
 */

/*
 * Lex for Attribute Table
 */

/* Definitions Section.
 * Definitions required by the rules section are in here prior to first
 * "%%" seperator
 */

/* Include code between "%{ %}" separators at top of generated
 * lexer source file
 */
%{
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include "sftarget_data.h"
#include "sf_attribute_table.h" /* Generated from YACC */

#ifdef DEBUG_MSGS
#undef DEBUG_MSGS  /* FIXIT */
#endif

extern ServiceClient sfat_client_or_service;

static int sfat_linenumber = 0;
static char* sfat_filename;
void sfat_error(char *err);
int sfat_parse(void);

/* Change flex buffer size from default 8K to SFAT_BUFSZ bytes */
#ifdef YY_BUF_SIZE
#undef  YY_BUF_SIZE
#endif
#define YY_BUF_SIZE SFAT_BUFSZ

#define YY_DECL int sfat_lex(void)

%}

/* At end-of-file return assuming no more files to scan */
%option noyywrap

/* Not using this functionality */
%option nounput
%option noinput

/* Optimise lexer for interactive use */
%option never-interactive

/* Declare exclusive start conditions.
 * Start conditions are included here to illustrate how to add simple
 * state-machine functionality to the lexer
 */
%x waiting_for_comma_prior_to_data
%x waiting_for_data

/* Define some common patterns for use below */
newline        \r\n|\n
whitespace     [ \t]*
comma          ,
digit          [0-9]
numericValue   [+-]?{digit}{1,16}
stringValue    [ \t_/\-a-zA-Z0-9,\.;:()#"'~`!@#$%^&*()=+\[\]|\{\}\?\\]{1,4096}
commentStart   \<!
commentEnd     \>
comment        {commentStart}.*{commentEnd}


/* Rules Section.
 * All rules are in here prior to second "%%" seperator
 */

%%
{whitespace}            { ; }  /* Handle empty whitespace */
\<SNORT_ATTRIBUTES\>    { return SF_START_SNORT_ATTRIBUTES; }
\<\/SNORT_ATTRIBUTES\>  { return SF_END_SNORT_ATTRIBUTES; }

\<ATTRIBUTE_MAP\>       { return SF_AT_START_MAP_TABLE; }
\<\/ATTRIBUTE_MAP\>     { return SF_AT_END_MAP_TABLE; }
\<ENTRY\>               { return SF_AT_START_ENTRY; }
\<\/ENTRY\>             { return SF_AT_END_ENTRY; }
\<ID\>                  { return SF_AT_START_ENTRY_ID; }
\<\/ID\>                { return SF_AT_END_ENTRY_ID; }
\<VALUE\>               { return SF_AT_START_ENTRY_VALUE; }
\<\/VALUE\>             { return SF_AT_END_ENTRY_VALUE; }
\<ATTRIBUTE_TABLE\>     { return SF_AT_START_ATTRIBUTE_TABLE; }
\<\/ATTRIBUTE_TABLE\>   { return SF_AT_END_ATTRIBUTE_TABLE; }
\<HOST\>                { return SF_AT_START_HOST; }
\<\/HOST\>              { return SF_AT_END_HOST; }
\<IP\>                  { return SF_AT_START_HOST_IP; }
\<\/IP\>                { return SF_AT_END_HOST_IP; }
\<OPERATING_SYSTEM\>    { return SF_AT_START_OS; }
\<\/OPERATING_SYSTEM\>  { return SF_AT_END_OS; }
\<ATTRIBUTE_VALUE\>     { return SF_AT_START_ATTRIBUTE_VALUE; }
\<\/ATTRIBUTE_VALUE\>   { return SF_AT_END_ATTRIBUTE_VALUE; }
\<ATTRIBUTE_ID\>        { return SF_AT_START_ATTRIBUTE_ID; }
\<\/ATTRIBUTE_ID\>      { return SF_AT_END_ATTRIBUTE_ID; }
\<CONFIDENCE\>          { return SF_AT_START_CONFIDENCE; }
\<\/CONFIDENCE\>        { return SF_AT_END_CONFIDENCE; }
\<NAME\>                { return SF_AT_START_NAME; }
\<\/NAME\>              { return SF_AT_END_NAME; }
\<VENDOR\>              { return SF_AT_START_VENDOR; }
\<\/VENDOR\>            { return SF_AT_END_VENDOR; }
\<VERSION\>             { return SF_AT_START_VERSION; }
\<\/VERSION\>           { return SF_AT_END_VERSION; }
\<FRAG_POLICY\>         { return SF_AT_START_FRAG_POLICY; }
\<\/FRAG_POLICY\>       { return SF_AT_END_FRAG_POLICY; }
\<STREAM_POLICY\>       { return SF_AT_START_STREAM_POLICY; }
\<\/STREAM_POLICY\>     { return SF_AT_END_STREAM_POLICY; }
\<SERVICES\>            { return SF_AT_START_SERVICES; }
\<\/SERVICES\>          { return SF_AT_END_SERVICES; }
\<SERVICE\>             { return SF_AT_START_SERVICE; }
\<\/SERVICE\>           { return SF_AT_END_SERVICE; }
\<CLIENTS\>             { return SF_AT_START_CLIENTS; }
\<\/CLIENTS\>           { return SF_AT_END_CLIENTS; }
\<CLIENT\>              { return SF_AT_START_CLIENT; }
\<\/CLIENT\>            { return SF_AT_END_CLIENT; }
\<IPPROTO\>             { return SF_AT_START_IPPROTO; }
\<\/IPPROTO\>           { return SF_AT_END_IPPROTO; }
\<PROTOCOL\>            { return SF_AT_START_PROTOCOL; }
\<\/PROTOCOL\>          { return SF_AT_END_PROTOCOL; }
\<PORT\>                { return SF_AT_START_PORT; }
\<\/PORT\>              { return SF_AT_END_PORT; }
\<APPLICATION\>         { return SF_AT_START_APPLICATION; }
\<\/APPLICATION\>       { return SF_AT_END_APPLICATION; }

{numericValue}          {
                            sfat_lval.numericValue = strtol( yytext, NULL, 10 );
#ifdef DEBUG_MSGS
                            DebugMessage(DEBUG_ATTRIBUTE,
                                "Number Value: [%d]\n", sfat_lval.numericValue);
#endif
                            return SF_AT_NUMERIC;
                        }
{stringValue}           {
                            /* Store the value of the string, but not
                             * more than SFAT_BUFSZ. */
                            unsigned i;
                            for (i=0; i < yyleng && i < SFAT_BUFSZ-1; i++)
                            {
                                sfat_lval.stringValue[i] = yytext[i];
                            }

                            sfat_lval.stringValue[i] = '\0';
#ifdef DEBUG_MSGS
                            DebugMessage(DEBUG_ATTRIBUTE,
                                "String Value: [%s]\n", sfat_lval.stringValue);
#endif
                            return SF_AT_STRING;
                        }
{newline}               { sfat_linenumber++; }
{comment}               { ; /* Do nothing -- ignore it */}

.                       { return 0; }
                        /* Error, no meaningful input provided */

<<EOF>>                 { yyterminate(); }

%%
char *sfat_grammar_error=NULL;
char sfat_grammar_error_printed=0;
char sfat_insufficient_space_logged=0;
char sfat_fatal_error=1;
char *sfat_saved_file = NULL;
static char sfat_saved_file_set = 0;
char parse_error = 0;
char sfat_error_message[SFAT_BUFSZ];
int ParseTargetMap(char *filename)
{
    int error;
    int ret = SFAT_ERROR;
    parse_error = 0;
    sfat_grammar_error_printed = 0;

    if (!filename)
    {
        return SFAT_OK;
    }

    yyin = fopen(filename, "r");
    if (!yyin)
    {
        snprintf(sfat_error_message, sizeof(sfat_error_message),
            "Failed to open target-based attribute file: '%s'\n",
            filename);
        sfat_error_message[sizeof(sfat_error_message)-1] = '\0';
        return ret;
    }
    sfat_filename = filename;

    if (feof(yyin))
    {
        snprintf(sfat_error_message, SFAT_BUFSZ,
            "Emtpy target-based attribute file: '%s'\n",
            filename);
        sfat_error_message[sizeof(sfat_error_message)-1] = '\0';
        fclose(yyin);
        return ret;
    }

    error = sfat_parse();
    if (error)
    {
        sfat_error("");
        fclose(yyin);
        return ret;
    }
    fclose(yyin);

    if (parse_error == 1)
    {
        return ret;
    }

    ret = SFAT_OK;
    /* Everything parsed ok, save off the filename */
    if (sfat_saved_file_set && sfat_saved_file)
    {
        if (!strcmp(sfat_saved_file, sfat_filename))
        {
            /* Same filename, we're done. */
            return ret;
        }
        sfat_saved_file_set = 0;
    }

    /* Save off the new filename. */
    if (sfat_saved_file)
    {
        free(sfat_saved_file);
    }
    sfat_saved_file = strdup(sfat_filename);
    sfat_saved_file_set = 1;

    return ret;
}

void DestroyBufferStack(void)
{
#ifdef HAVE_YYLEX_DESTROY
    sfatlex_destroy();
#endif
}

void sfat_error(char* err)
{
    (void)err;  /* mark unused */

    if (sfat_grammar_error_printed != 0)
    {
        parse_error = 1;
        return;
    }

    if (sfat_grammar_error)
    {
        snprintf(sfat_error_message, sizeof(sfat_error_message),
            "Invalid Attribute Table specification: '%s'.\n"
            "Please verify the grammar at or near line %d (tag '%s'): %s\n",
            sfat_filename, sfat_linenumber, yytext, sfat_grammar_error);
        sfat_error_message[sizeof(sfat_error_message)-1] = '\0';
    }
    else
    {
        snprintf(sfat_error_message, sizeof(sfat_error_message),
            "Invalid Attribute Table specification: '%s'.\n"
            "Please verify the grammar at or near line %d (tag '%s').\n",
            sfat_filename, sfat_linenumber, yytext);
        sfat_error_message[sizeof(sfat_error_message)-1] = '\0';
    }
    parse_error = 1;
}

