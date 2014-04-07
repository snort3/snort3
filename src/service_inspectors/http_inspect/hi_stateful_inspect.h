/****************************************************************************
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2005-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/
 

/*
 * hi_stateful_inspect.h: Defines, structs, function prototype(s) for
 *	HTTP inspect stateful inspection module.
 *
 * Author(s): Chris Sherwin
 */

#ifndef HI_STATEFUL_INSPECT_H
#define HI_STATEFUL_INSPECT_H

/*
 * Flags modifying stateful inspection's behavior 
 * 
 * HI_ST_FLG_CLEAR:		No flags set
 * HI_ST_FLG_CRLF_EOM:		Found a CRLF at the end of 
 *				the previous pkt.
 * HI_ST_FLG_POSTPARM:		Request contains post parameters.
 */
#define HI_ST_FLG_CLEAR		(0x0)
#define HI_ST_FLG_CRLF_EOM	(0x1)
#define HI_ST_FLG_POSTPARM	(0x2)

/*
 * States into which the HTTP request
 * stateful processing can enter.
 *
 * HI_ST_STATE_URI_KEY: HTTP Inspect is searching for 
 *			request method keyword which
 *			signifies URI.
 * HI_ST_STATE_URI_CONT: HTTP Inspect is building the
 *			contents of the URI.
 * HI_ST_STATE_HDR_KEY: HTTP Inspect is searching for
 *			a header keyword.
 * HI_ST_STATE_HDR_CT: HTTP Inspect is processing a 
 *			content-type header.
 * HI_ST_STATE_HDR_PA: HTTP Inspect is processing a 
 *			proxy-authenticate header.
 * HI_ST_STATE_HDR_CONT: HTTP Inspect is examining the 
 *			contents of a header.
 * HI_ST_STATE_BDY_POST: HTTP Inspect is treating body
 *			as a set of post parameters.
 * HI_ST_STATE_BDY_PIPE: HTTP Inspect is searching for 
 *			 a pipelined request.
 * HI_ST_STATE_MSG_DONE: A complete HTTP request has 
 *			been seen and processed.
 */
#define HI_ST_STATE_URI_KEY	(0x1)
#define HI_ST_STATE_URI_CONT	(0x2)
#define HI_ST_STATE_HDR_KEY	(0x3)
#define HI_ST_STATE_HDR_CT	(0x4)
#define HI_ST_STATE_HDR_PA	(0x5)
#define HI_ST_STATE_HDR_CONT	(0x6)
#define HI_ST_STATE_BDY_POST	(0x7)
#define HI_ST_STATE_BDY_PIPE	(0x8)
#define HI_ST_STATE_MSG_DONE	(0x9)
#define HI_ST_NUM_STATES	(8)

/*
 *
 */
#define HI_ST_MAXBUFLEN		10400

/*
 * Recognized delimiter types.
 */
#define HI_ST_DELIM_NONE	(0x0)
#define HI_ST_DELIM_CRLF	(0x1)
#define HI_ST_DELIM_AHF		(0x2)

#define HI_ST_SUCCESS	(0x1)
#define HI_ST_FAILURE	(0x0)

/*
 * Flag values for BUFFER::buf_flags. These
 * define any special processing of the buffer
 * that may be needed/pending.
 *
 * HI_ST_BUFFLGS_NONE:		No flags.
 * HI_ST_BUFFLGS_COMPACT: 	Buffer "compacting" is required
 */
#define HI_ST_BUFFLGS_NONE	(0x0)
#define HI_ST_BUFFLGS_COMPACT 	(0x1)

#define HI_ST_MAX_BYTES_WO_HEADER 10

/*
 * Default value for max header bytes. Used for 
 * header folding detection, etc. to alert on
 * suspiciously long header fields.
 */
#define HI_ST_MAX_HEADER_BYTES	8190

/* Buffer structure used in stateful inspection
 * packet processing.
 *
 * startp:    Start of actual data in buffer.
 * endp:      End of actual data in buffer.
 * curp:      Pointer/index into the buffer data.
 * bufendp:   End of the allocated memory for the buffer.
 * buf_flags: Flags indicating special processing which is required.
 */
typedef struct _BUF
{
	unsigned char* startp;
	unsigned char* endp;
	unsigned char* curp;
	unsigned char* bufendp;
	unsigned int buf_flags;
} BUFFER;

/* Structure containing current state regarding headers for 
 * a request.
 *
 * num_headers:	Number of headers seen in the current request.
 * bytes_wo_header: Bytes examined since last header, w/o finding
 *			a new header.
 * hf_bytes: Bytes examined so far in current header. Used for
 *		header folding inspection.
 * startp:   Pointer to start of headers section of request.
 * endp:     Pointer to end of headers section of request.
 * base64startp: Pointer to start of base64 encoded portion of req.
 * base64endp:   Pointer to end of base64 encoded portion of req.
 *
 */
typedef struct _HEADER_STATE
{
	int num_headers;
	int bytes_wo_header;
	int hf_bytes;
	unsigned char* startp;
	unsigned char* endp;
	unsigned char* base64startp;
	unsigned char* base64endp;
} HEADER_STATE;

/*
 * One of these structures is kept for each HTTP session
 * tracked by HTTP inspect.
 *
 * request_buffer:
 * mpse_state:    Saved MPSE state from searches started in 
 *                      previous packet
 * flags: 	  State flags
 * state:	  Current state of the inspectin state machine.
 * request_type:  Discovered method type for current request.
 * uristate:	  State block containing discovered info about
 *			URI in current request.
 * headerstate:	  State block containing discovered info about headers
 *			in current request.
 * bodyp:	  Pointer to beginning of body portion of request.
 * body_endp:     Pointer to end of body portion of request.
 */
typedef struct _HI_SI_STATE
{
	BUFFER request_buffer;
	int mpse_state;
	int flags;
	int state;
	int request_type;
	URI_PTR uristate;
	HEADER_STATE headerstate;
	unsigned char* bodyp;
	unsigned char* body_endp;
} HI_SI_STATE;

/*
 * Match-types to be filled into HI_SI_MATCHDATA::type
 *
 * HI_ST_MATCHTYPE_NONE:	No match
 * HI_ST_MATCHTYPE_REQMETHOD:	A req. method keyword has been found.
 * HI_ST_MATCHTYPE_HEADER:	A header keyword has been found.
 * HI_ST_MATCHTYPE_CRLF:	A delimiter token has been found.
 * HI_ST_MATCHTYPE_POSTPARMCT:	The post-param content-type has been found.
 * HI_ST_MATCHTYPE_BASE64:	A keyword indicating base64 enc. has been found.
 */
#define HI_ST_MATCHTYPE_NONE		(0x0)
#define HI_ST_MATCHTYPE_REQMETHOD	(0x1)
#define HI_ST_MATCHTYPE_HEADER		(0x2)
#define HI_ST_MATCHTYPE_CRLF		(0x3)
#define HI_ST_MATCHTYPE_POSTPARMCT	(0x4)
#define HI_ST_MATCHTYPE_BASE64		(0x5)

#define HI_ST_CT_KEYWORD "Content-Type:"
#define HI_ST_PA_KEYWORD "Proxy-Authorization:"

/*
 * Request method types
 */
#define HI_ST_METHOD_GET	(0x1)
#define HI_ST_METHOD_HEAD	(0x2)
#define HI_ST_METHOD_POST	(0x3)
#define HI_ST_METHOD_PUT	(0x4)
#define HI_ST_METHOD_DELETE	(0x5)
#define HI_ST_METHOD_TRACE	(0x6)
#define HI_ST_METHOD_CONNECT	(0x7)

/* One of these structs is passed into the MPSE search
 * to be filled in by the match callback.
 *
 * index: The index of the match, in bytes, 
 *			into the searched string
 * type:  The type of keyword found 
 *			(e.g. request method or header )
 * data:  Type-specific data.
 *
 * keywordp: Pointer to the keyword which matched.
 */
typedef struct _HI_SI_MATCHDATA
{
	int index;
	int type;
	int data;
	unsigned char* keywordp;
} HI_SI_MATCHDATA;

#endif /* HI_STATEFUL_INSPECT_H */
