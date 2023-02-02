#!/bin/bash

##--------------------------------------------------------------------------
## Copyright (C) 2015-2022 Cisco and/or its affiliates. All rights reserved.
##
## This program is free software; you can redistribute it and/or modify it
## under the terms of the GNU General Public License Version 2 as published
## by the Free Software Foundation.  You may not use, modify or distribute
## this program under any other version of the GNU General Public License.
##
## This program is distributed in the hope that it will be useful, but
## WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
## General Public License for more details.
##
## You should have received a copy of the GNU General Public License along
## with this program; if not, write to the Free Software Foundation, Inc.,
## 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
##--------------------------------------------------------------------------

##--------------------------------------------------------------------
## Generate custom lua detector for appid
##--------------------------------------------------------------------

echo "Snort Application Id - Detector Creation Tool"
echo ""
function protocol_prompt()
{
local retval="zzz"
local choice_list=( "TCP" "UDP" "HTTP" "SSL" "SIP" "RTMP" "First Packet")
echo ""
if [[ "$protocol_loop" = "atleastonce" ]]; then
    choice_list=( "Save Detector" "${choice_list[@]}" )
    echo -e "Choose \"Save Detector\" or choose an additional Detection Protocol:"
else
    echo "Detection Protocol:"
fi
PS3="Selection: "
select retval in "${choice_list[@]}";
do
case $retval in
    "TCP")
        protocol_string="proto"
        protocol_choice=$retval
        first_packet_only="0"
        break
        ;;
    "UDP")
        protocol_string="DC.ipproto.udp"
        protocol_choice=$retval
        first_packet_only="0"
        break
        ;;
    "HTTP")
        protocol_choice=$retval
        first_packet_only="0"
        break
        ;;
    "SSL")
        protocol_choice=$retval
        first_packet_only="0"
        break
        ;;
    "SIP")
        protocol_choice=$retval
        first_packet_only="0"
        break
        ;;
    "RTMP")
        protocol_choice=$retval
        first_packet_only="0"
        break
        ;;
    "First Packet")
        protocol_choice=$retval
        if [[ ${first_packet_only} = "-1" ]]; then
            first_packet_only="1"
        fi
        break
        ;;
    "Save Detector")
        protocol_choice="Q"
        break
        ;;
        * )
        # go around again, repeating the preamble
        if [[ "$protocol_loop" = "atleastonce" ]]; then
            echo "enter a number between 1-7"
        else
            echo "enter a number between 1-6"
        fi
        echo ""
        ;;
esac
done
protocol_loop="atleastonce"
}
function pattern_type_prompt()
{
local answer="zzz"
echo "Pattern Type:"
PS3="Selection: "
select answer in "ASCII" "HEX"; do
case "$answer" in
    "ASCII" | "HEX")
        pattern_type_choice=$answer
        break
        ;;
    *)
        echo "enter a number between 1-2"
        echo ""
        ;;
esac
done
}
function pattern_prompt()
{
	read -p "Enter $1 pattern: " pattern_string
}
function hex_pattern_prompt()
{
local retval="==0=="
while [[ "$retval" = "==0==" ]]; do
	echo "Enter pattern, (1 or 2 hex digits per byte, separated by spaces):"
#read the bytes as parsed words of two letters into an array
	read retval
if [[ "$retval" = "" ]]; then
	retval="==0=="
else
local pattern_bytes=($retval)
unset pattern_string
i=0;
while [[ ${#pattern_bytes[i]} -gt 0 ]]; do
	if [[ ${#pattern_bytes[i]} -eq 1 ]]; then
		pattern_string=${pattern_string}\\x0${pattern_bytes[i]}
	else
		pattern_string=${pattern_string}\\x${pattern_bytes[i]}
	fi
	i=$(( i + 1 ))
done
	unset retval
fi
done
}
function first_packet_pattern_prompt()
{
local retval="==0=="
if [[ "${first_packet_protocol_appid}" = "" ]]; then
    read -p "Enter Protocol AppId: " first_packet_protocol_appid
    read -p "Enter Client AppId: " first_packet_client_appid
    read -p "Enter Web AppId: " first_packet_webapp_appid
fi
read -p "Enter Server IP: " pattern_string
local choice_list=( "TCP" "UDP" )
echo "Protocol Type:"
PS3="Selection: "
select retval in "${choice_list[@]}";
do
case $retval in
    "TCP")
        first_packet_protocol_string="proto"
        break
        ;;
    "UDP")
        first_packet_protocol_string="DC.ipproto.udp"
        break
        ;;
esac
done
choice_list=( "True" "False" )
echo "Perform reinspection:"
PS3="Selection: "
select retval in "${choice_list[@]}";
do
case $retval in
    "True")
        first_packet_reinspect_flag="1"
        break
        ;;
    "False")
        first_packet_reinspect_flag="0"
        break
        ;;
esac
done
}
function offset_number_prompt()
{
local decimal_answer
	read -p "Enter Offset (decimal): " decimal_answer
	pattern_offset=${decimal_answer:=-1}
}
function port_numbers_prompt()
{
	local decimal_answer
	read -p "Enter Port(s) (decimal, separated by spaces): " decimal_answer
	port=($decimal_answer)
	if [[ "$decimal_answer" = "" ]]; then
		unset port
		port="-1"
	fi
}
function set_client_vs_server()
{
if [[ "$client_vs_server" != "BOTH" ]]; then
	if [[ "$client_vs_server" = "" ]]; then
		client_vs_server=$1
	else
		if [[ "$client_vs_server" != "$1" ]]; then
			client_vs_server="BOTH"
		fi
	fi
fi
}
function direction_prompt()
{
echo "Direction:"
echo "1) Client"
echo "2) Server (default)"
read -p "Selection: " answer
case "$answer" in
    1)
        direction_choice="CLIENT"
        ;;
    *)
        direction_choice="SERVER"
        ;;
esac
# we need to remember this as we add patterns for client and/or server
set_client_vs_server "$direction_choice"
}
function http_pattern_type_prompt()
{
local answer="zzz"
echo "HTTP Pattern Type:"
PS3="Selection: "
select answer in "URL" "User Agent" "Content Type"; do
case "$answer" in
    "URL" | "User Agent" | "Content Type")
        pattern_type_choice="$answer"
        break
        ;;
    *)
        echo "enter a number between 1-3"
        echo ""
        ;;
esac
done
}
function ssl_pattern_type_prompt()
{
local answer="zzz"
echo "SSL Pattern Type:"
PS3="Selection: "
select answer in "Host" "Common Name" "Organizational Unit"; do
case "$answer" in
    "Host" | "Common Name" | "Organizational Unit")
        pattern_type_choice="$answer"
        break
        ;;
    *)
        echo "enter a number between 1-3"
        echo ""
        ;;
esac
done
}
function sip_pattern_type_prompt()
{
local answer="zzz"
echo "SIP Pattern Type:"
PS3="Selection: "
select answer in "SIP Server" "User Agent"; do
case "$answer" in
    "SIP Server" | "User Agent")
        pattern_type_choice="$answer"
        break
        ;;
    *)
        echo "enter a number between 1-2"
        echo ""
        ;;
esac
done
}
function output_preamble()
{
echo -e "--[[" >"${OUTPUTFILE}"
echo -e "detection_name: $APPDETECTORNAME" >>"${OUTPUTFILE}"
echo -e "version: 1" >>"${OUTPUTFILE}"
echo -e "description: $APPDETECTORDESC" >>"${OUTPUTFILE}"
echo -e "--]]"  >>"${OUTPUTFILE}"
echo -e ""  >>"${OUTPUTFILE}"
echo -e "require \"DetectorCommon\"" >>"${OUTPUTFILE}"
echo -e "local DC = DetectorCommon" >>"${OUTPUTFILE}"
echo -e "" >>"${OUTPUTFILE}"
echo -e "local proto = DC.ipproto.tcp;" >>"${OUTPUTFILE}"
echo -e "DetectorPackageInfo = {" >>"${OUTPUTFILE}"
echo -e "\tname = \"$APPDETECTORNAME\"," >>"${OUTPUTFILE}"
echo -e "\tproto = proto," >>"${OUTPUTFILE}"
case "$client_vs_server" in
    "CLIENT")
        echo -e "\tclient = {" >>"${OUTPUTFILE}"
        echo -e "\t\tinit = 'DetectorInit'," >>"${OUTPUTFILE}"
        echo -e "\t\tclean = 'DetectorClean'," >>"${OUTPUTFILE}"
        echo -e "\t\tminimum_matches = 1" >>"${OUTPUTFILE}"
        echo -e "\t}" >>"${OUTPUTFILE}"
        ;;
	"SERVER")
        echo -e "\tserver = {" >>"${OUTPUTFILE}"
        echo -e "\t\tinit = 'DetectorInit'," >>"${OUTPUTFILE}"
        echo -e "\t\tclean = 'DetectorClean'," >>"${OUTPUTFILE}"
        echo -e "\t\tminimum_matches = 1" >>"${OUTPUTFILE}"
        echo -e "\t}" >>"${OUTPUTFILE}"
        ;;
	"BOTH")
        echo -e "\tclient = {" >>"${OUTPUTFILE}"
        echo -e "\t\tinit = 'DetectorInit'," >>"${OUTPUTFILE}"
        echo -e "\t\tclean = 'DetectorClean'," >>"${OUTPUTFILE}"
        echo -e "\t\tminimum_matches = 1" >>"${OUTPUTFILE}"
        echo -e "\t}," >>"${OUTPUTFILE}"
        echo -e "\tserver = {" >>"${OUTPUTFILE}"
        echo -e "\t\tminimum_matches = 1" >>"${OUTPUTFILE}"
        echo -e "\t}" >>"${OUTPUTFILE}"
		;;
esac
echo -e "}" >>"${OUTPUTFILE}"
echo -e "" >>"${OUTPUTFILE}"
}
function output_detectorinit_preamble()
{
echo -e "function DetectorInit(detectorInstance)" >>"${OUTPUTFILE}"
echo -e "" >>"${OUTPUTFILE}"
echo -e "\tgDetector = detectorInstance;" >>"${OUTPUTFILE}"
if [[ -f "$INTERMEDIATEFILE_FIRST_PACKET" ]]; then
    echo -en "\tgProtocolAppId = gDetector:open_createApp(\"" >>"${OUTPUTFILE}"
    echo -n "${first_packet_protocol_appid}" >>"${OUTPUTFILE}"
    echo -e "\");" >>"${OUTPUTFILE}"
    echo -en "\tgClientAppId = gDetector:open_createApp(\"" >>"${OUTPUTFILE}"
    echo -n "${first_packet_client_appid}" >>"${OUTPUTFILE}"
    echo -e "\");" >>"${OUTPUTFILE}"
    echo -en "\tgWebAppAppId = gDetector:open_createApp(\"" >>"${OUTPUTFILE}"
    echo -n "${first_packet_webapp_appid}" >>"${OUTPUTFILE}"
    echo -e "\");" >>"${OUTPUTFILE}"
    echo -e "" >>"${OUTPUTFILE}"
fi

if [[ ${first_packet_only} = "0" ]]; then
    echo -en "\tgAppId = gDetector:open_createApp(\"" >>"${OUTPUTFILE}"
    echo -n "${APPIDSTRING}" >>"${OUTPUTFILE}"
    echo -e "\");" >>"${OUTPUTFILE}"
    echo -e "" >>"${OUTPUTFILE}"
fi
}
function output_detectorinit_postlude()
{
echo -e "" >>"${OUTPUTFILE}"
echo -e "\treturn gDetector;" >>"${OUTPUTFILE}"
echo -e "end" >>"${OUTPUTFILE}"
}
function output_detectorclean_preamble()
{
echo -e "" >>"${OUTPUTFILE}"
echo -e "function DetectorClean()" >>"${OUTPUTFILE}"
}
function output_detectorclean_postlude()
{
echo -e "end" >>"${OUTPUTFILE}"
}
function output_port_pattern_client()
{
echo -en "\t\tgDetector:addPortPatternClient($protocol_string,\"" >>"${INTERMEDIATEFILE_CLIENT}"
echo -n "${pattern_string}" >>"${INTERMEDIATEFILE_CLIENT}"
echo -e "\",$pattern_offset, gAppId);" >>"${INTERMEDIATEFILE_CLIENT}"
}
function output_optional_client()
{
if [[ -f "$INTERMEDIATEFILE_CLIENT" ]]; then
echo -e "\tif gDetector.addPortPatternClient then" >>"${OUTPUTFILE}"
cat "${INTERMEDIATEFILE_CLIENT}" >>"${OUTPUTFILE}"
echo -e "\tend" >>"${OUTPUTFILE}"
rm "${INTERMEDIATEFILE_CLIENT}"
fi
}
function output_port_pattern_server()
{
if [[ "$port" = "-1" ]]; then
echo -en "\t\tgDetector:addPortPatternService($protocol_string,0,\"" >>"${INTERMEDIATEFILE_SERVER}"
echo -n "${pattern_string}" >>"${INTERMEDIATEFILE_SERVER}"
echo -e "\",$pattern_offset, gAppId);" >>"${INTERMEDIATEFILE_SERVER}"
else
local i=0;
while [[ "${port[i]}" != "" ]]; do
echo -en "\t\tgDetector:addPortPatternService($protocol_string,${port[i]},\"" >>"${INTERMEDIATEFILE_SERVER}"
echo -n "${pattern_string}" >>"${INTERMEDIATEFILE_SERVER}"
echo -e "\",$pattern_offset, gAppId);" >>"${INTERMEDIATEFILE_SERVER}"
i=$(( $i + 1 ))
done
fi
}
function output_optional_server()
{
if [[ -f "$INTERMEDIATEFILE_SERVER" ]]; then
	echo -e "\tif gDetector.addPortPatternService then" >>"${OUTPUTFILE}"
	cat "${INTERMEDIATEFILE_SERVER}" >>"${OUTPUTFILE}"
	echo -e "\tend" >>"${OUTPUTFILE}"
	rm "${INTERMEDIATEFILE_SERVER}"
fi
}
function output_http_url_pattern()
{
# the URL protocol component (e.g. "http://"), if provided is removed.
pattern_string=${pattern_string#*://}
# the URL path component is everything after the first "/" so keep everything to the right in pattern_path
pattern_path=${pattern_string#*/}
# the URL host component is everything before the first "/" so keep everything to the left in pattern_host
pattern_host=${pattern_string%%/*}
if [[ "${pattern_host}" == "${pattern_string}" ]]; then
    # no path included
    pattern_path="/"
else
    pattern_path="/${pattern_path}"
    while [[ $pattern_path == *"//"* ]]
    do
        pattern_path=${pattern_path//\/\//\/}
    done
fi
echo -en "\t\tgDetector:addAppUrl(0, 0, 0, gAppId, 0, \"" >>"${INTERMEDIATEFILE_HTTP_URL}"
echo -n "${pattern_host}" >>"${INTERMEDIATEFILE_HTTP_URL}"
echo -en "\", \"" >>"${INTERMEDIATEFILE_HTTP_URL}"
echo -n "${pattern_path}" >>"${INTERMEDIATEFILE_HTTP_URL}"
echo -e "\", \"http:\", \"\", gAppId);" >>"${INTERMEDIATEFILE_HTTP_URL}"
}
function output_optional_http_url()
{
if [[ -f "$INTERMEDIATEFILE_HTTP_URL" ]]; then
echo -e "\tif gDetector.addAppUrl then" >>"${OUTPUTFILE}"
cat "${INTERMEDIATEFILE_HTTP_URL}" >>"${OUTPUTFILE}"
echo -e "\tend" >>"${OUTPUTFILE}"
rm "${INTERMEDIATEFILE_HTTP_URL}"
fi
}
function output_http_useragent_pattern()
{
echo -en "\t\tgDetector:addHttpPattern(2, 5, 0, gAppId, 0, 0, 0, \"" >>"${INTERMEDIATEFILE_HTTP_USER_AGENT}"
echo -n "${pattern_string}" >>"${INTERMEDIATEFILE_HTTP_USER_AGENT}"
echo -e "\", gAppId);" >>"${INTERMEDIATEFILE_HTTP_USER_AGENT}"
}
function output_optional_http_useragent()
{
if [[ -f "$INTERMEDIATEFILE_HTTP_USER_AGENT" ]]; then
echo -e "\tif gDetector.addHttpPattern then" >>"${OUTPUTFILE}"
cat "${INTERMEDIATEFILE_HTTP_USER_AGENT}" >>"${OUTPUTFILE}"
echo -e "\tend" >>"${OUTPUTFILE}"
rm "${INTERMEDIATEFILE_HTTP_USER_AGENT}"
fi
}
function output_http_contenttype_pattern()
{
echo -en "\t\tgDetector:addContentTypePattern(\"" >>"${INTERMEDIATEFILE_HTTP_CONTENT_TYPE}"
echo -n "${pattern_string}" >>"${INTERMEDIATEFILE_HTTP_CONTENT_TYPE}"
echo -e "\", gAppId);" >>"${INTERMEDIATEFILE_HTTP_CONTENT_TYPE}"
}
function output_optional_http_contenttype()
{
if [[ -f "$INTERMEDIATEFILE_HTTP_CONTENT_TYPE" ]]; then
echo -e "\tif gDetector.addContentTypePattern then" >>"${OUTPUTFILE}"
cat "${INTERMEDIATEFILE_HTTP_CONTENT_TYPE}" >>"${OUTPUTFILE}"
echo -e "\tend" >>"${OUTPUTFILE}"
rm "${INTERMEDIATEFILE_HTTP_CONTENT_TYPE}"
fi
}
function output_ssl_host_pattern()
{
echo -en "\t\tgDetector:addSSLCertPattern(0, gAppId, \"" >>"${INTERMEDIATEFILE_SSL_HOST}"
echo -n "${pattern_string}" >>"${INTERMEDIATEFILE_SSL_HOST}"
echo -e "\");" >>"${INTERMEDIATEFILE_SSL_HOST}"
}
function output_optional_ssl_host()
{
if [[ -f "$INTERMEDIATEFILE_SSL_HOST" ]]; then
echo -e "\tif gDetector.addSSLCertPattern then" >>"${OUTPUTFILE}"
cat "${INTERMEDIATEFILE_SSL_HOST}" >>"${OUTPUTFILE}"
echo -e "\tend" >>"${OUTPUTFILE}"
rm "${INTERMEDIATEFILE_SSL_HOST}"
fi
}
function output_ssl_cn_pattern()
{
echo -en "\t\tgDetector:addSSLCnamePattern(0, gAppId, \"" >>"${INTERMEDIATEFILE_SSL_CN}"
echo -n "${pattern_string}" >>"${INTERMEDIATEFILE_SSL_CN}"
echo -e "\");" >>"${INTERMEDIATEFILE_SSL_CN}"
}
function output_optional_ssl_cn()
{
if [[ -f "$INTERMEDIATEFILE_SSL_CN" ]]; then
echo -e "\tif gDetector.addSSLCnamePattern then" >>"${OUTPUTFILE}"
cat "${INTERMEDIATEFILE_SSL_CN}" >>"${OUTPUTFILE}"
echo -e "\tend" >>"${OUTPUTFILE}"
rm "${INTERMEDIATEFILE_SSL_CN}"
fi
}
function output_sip_server_pattern()
{
echo -en "\t\tgDetector:addSipServer(gAppId, \"\", \"" >>"${INTERMEDIATEFILE_SIP_SERVER}"
echo -n "${pattern_string}" >>"${INTERMEDIATEFILE_SIP_SERVER}"
echo -e "\");" >>"${INTERMEDIATEFILE_SIP_SERVER}"
}
function output_optional_sip_server()
{
if [[ -f "$INTERMEDIATEFILE_SIP_SERVER" ]]; then
echo -e "\tif gDetector.addSipServer then" >>"${OUTPUTFILE}"
cat "${INTERMEDIATEFILE_SIP_SERVER}" >>"${OUTPUTFILE}"
echo -e "\tend" >>"${OUTPUTFILE}"
rm "${INTERMEDIATEFILE_SIP_SERVER}"
fi
}
function output_sip_useragent_pattern()
{
echo -en "\t\tgDetector:addSipUserAgent(gAppId, \"\", \"" >>"${INTERMEDIATEFILE_SIP_USER_AGENT}"
echo -n "${pattern_string}" >>"${INTERMEDIATEFILE_SIP_USER_AGENT}"
echo -e "\");" >>"${INTERMEDIATEFILE_SIP_USER_AGENT}"
}
function output_optional_sip_useragent()
{
if [[ -f "$INTERMEDIATEFILE_SIP_USER_AGENT" ]]; then
echo -e "\tif gDetector.addSipUserAgent then" >>"${OUTPUTFILE}"
cat "${INTERMEDIATEFILE_SIP_USER_AGENT}" >>"${OUTPUTFILE}"
echo -e "\tend" >>"${OUTPUTFILE}"
rm "${INTERMEDIATEFILE_SIP_USER_AGENT}"
fi
}
function output_rtmp_url_pattern()
{
echo -en "\t\tgDetector:addRTMPUrl(0, 0, 0, gAppId, 0, \"" >>"${INTERMEDIATEFILE_RTMP_URL}"
echo -n "${pattern_string}" >>"${INTERMEDIATEFILE_RTMP_URL}"
echo -e "\", \"/\", \"http:\", \"\", gAppId);" >>"${INTERMEDIATEFILE_RTMP_URL}"
}
function output_optional_rtmp_url()
{
if [[ -f "$INTERMEDIATEFILE_RTMP_URL" ]]; then
echo -e "\tif gDetector.addRTMPUrl then" >>"${OUTPUTFILE}"
cat "${INTERMEDIATEFILE_RTMP_URL}" >>"${OUTPUTFILE}"
echo -e "\tend" >>"${OUTPUTFILE}"
rm "${INTERMEDIATEFILE_RTMP_URL}"
fi
}
function output_first_packet_pattern()
{
if [[ "$port" = "-1" ]]; then
    port="0"
fi
local i=0;
while [[ "${port[i]}" != "" ]]; do
    echo -en "\t\tgDetector:addHostFirstPktApp(" >> "${INTERMEDIATEFILE_FIRST_PACKET}"
    echo -e "gProtocolAppId, gClientAppId, gWebAppAppId, ${first_packet_reinspect_flag}, \"${pattern_string}\", "${port[i]}", "${first_packet_protocol_string}")" >> "${INTERMEDIATEFILE_FIRST_PACKET}"
    i=$(( $i + 1 ))
done
}
function output_optional_first_packet_pattern()
{
if [[ -f "$INTERMEDIATEFILE_FIRST_PACKET" ]]; then
    echo -e "\tif gDetector.addHostFirstPktApp then" >> "${OUTPUTFILE}"
    cat "${INTERMEDIATEFILE_FIRST_PACKET}" >> "${OUTPUTFILE}"
    echo -e "\tend" >> "${OUTPUTFILE}"
    rm "${INTERMEDIATEFILE_FIRST_PACKET}"
fi
}
function clean_up_APPIDSTRING()
{
    APPIDSTRING=${APPIDSTRING//	/ }
    while [[ $APPIDSTRING == *"  "* ]]
    do
        APPIDSTRING=${APPIDSTRING//  / }
    done
    APPIDSTRING=${APPIDSTRING/# /}
    APPIDSTRING=${APPIDSTRING/% /}
    APPIDSTRING=${APPIDSTRING//[\\\'\"]/}
}
function clean_up_APPDETECTORDESC()
{
    APPDETECTORDESC=${APPDETECTORDESC//	/ }
    while [[ $APPDETECTORDESC == *"  "* ]]
    do
        APPDETECTORDESC=${APPDETECTORDESC//  / }
    done
    APPDETECTORDESC=${APPDETECTORDESC/# /}
    APPDETECTORDESC=${APPDETECTORDESC/% /}
}
function derive_cleaned_up_APPDETECTORNAME()
{
    APPDETECTORNAME=$1
    # convert spaces to underscores. Leading and trailing are already removed.
    APPDETECTORNAME=${APPDETECTORNAME// /_}
    # watch out for previously existing underscores next to the spaces
    while [[ $APPDETECTORNAME == *"__"* ]]
    do
        APPDETECTORNAME=${APPDETECTORNAME//__/_}
    done
    # convert taboo filename characters to '."
    APPDETECTORNAME=${APPDETECTORNAME//[\/><|:&]/.}
    # watch out for multiples next to each other
    while [[ $APPDETECTORNAME == *".."* ]]
    do
        APPDETECTORNAME=${APPDETECTORNAME//../.}
    done
    # watch for leading '.' since we will not want a name ls can't see by default.
    APPDETECTORNAME=${APPDETECTORNAME/#./}
    # watch for trailing '.' since "something..lua" is ugly.
    APPDETECTORNAME=${APPDETECTORNAME/%./}
}
###### begin main ########
echo -e "Enter below, the AppId string to be associated with the Detector."
echo -e "(e.g. \"CNN.com\", \"Yahoo!\", \"Avira Download/Update\", etc.)"
echo -e "AppId strings MUST NOT INCLUDE tab, backslash, apostrophe, or double-quote."
echo -e ""
read -p "Enter AppId string: " APPIDSTRING
clean_up_APPIDSTRING
first_packet_only="-1"
if [[ "z${APPIDSTRING// /}" = "z" ]]; then
    echo "requires a non-empty string."
    exit 0
fi
derive_cleaned_up_APPDETECTORNAME "$APPIDSTRING"
echo -e ""
read -p "Enter its optional description: " APPDETECTORDESC
clean_up_APPDETECTORDESC
if [[ "z${APPDETECTORDESC// /}" = "z" ]]; then
    # give it a default and move on
	APPDETECTORDESC="$APPDETECTORNAME wants a better description."
fi
### Name the output file, deriving if from APPDETECTORNAME
APPDETECTORFNAME="$APPDETECTORNAME"

MYHOME=$PWD
OUTPUTFILE="$MYHOME/$APPDETECTORFNAME.lua"
### Name all of the temporary files which will be merged into the output
INTERMEDIATEFILE_CLIENT="$MYHOME/$APPDETECTORFNAME.client.temp"
INTERMEDIATEFILE_SERVER="$MYHOME/$APPDETECTORFNAME.server.temp"
INTERMEDIATEFILE_HTTP_URL="$MYHOME/$APPDETECTORFNAME.http.url.temp"
INTERMEDIATEFILE_HTTP_USER_AGENT="$MYHOME/$APPDETECTORFNAME.http.user.agent.temp"
INTERMEDIATEFILE_HTTP_CONTENT_TYPE="$MYHOME/$APPDETECTORFNAME.http.content.type.temp"
INTERMEDIATEFILE_SSL_HOST="$MYHOME/$APPDETECTORFNAME.ssl.host.temp"
INTERMEDIATEFILE_SSL_CN="$MYHOME/$APPDETECTORFNAME.ssl.cn.temp"
INTERMEDIATEFILE_SIP_SERVER="$MYHOME/$APPDETECTORFNAME.sip.server.temp"
INTERMEDIATEFILE_SIP_USER_AGENT="$MYHOME/$APPDETECTORFNAME.sip.user.agent.temp"
INTERMEDIATEFILE_RTMP_URL="$MYHOME/$APPDETECTORFNAME.rtmp.url.temp"
INTERMEDIATEFILE_FIRST_PACKET="$MYHOME/$APPDETECTORFNAME.fp.tmp"
if [[ -f "$OUTPUTFILE" ]]; then
    echo "$OUTPUTFILE will be overwritten."
    read -p "Is this acceptable? [n]: " answer
    answer=${answer:=n}
    if [[ "$answer" != "Y" ]] ; then
        if [[ "$answer" != "y" ]] ; then
            echo "cancelling..."
            exit 0
        fi
    fi
fi
# Guarantee that the intermediate files start empty so we can append into them
rm -f "${INTERMEDIATEFILE_CLIENT}"
rm -f "${INTERMEDIATEFILE_SERVER}"
rm -f "${INTERMEDIATEFILE_HTTP_URL}"
rm -f "${INTERMEDIATEFILE_HTTP_USER_AGENT}"
rm -f "${INTERMEDIATEFILE_HTTP_CONTENT_TYPE}"
rm -f "${INTERMEDIATEFILE_SSL_HOST}"
rm -f "${INTERMEDIATEFILE_SSL_CN}"
rm -f "${INTERMEDIATEFILE_SIP_SERVER}"
rm -f "${INTERMEDIATEFILE_SIP_USER_AGENT}"
rm -f "${INTERMEDIATEFILE_RTMP_URL}"
rm -f "${INTERMEDIATEFILE_FIRST_PACKET}"
#### outer menu loop ####
protocol_prompt
while [[ "$protocol_choice" != "Q" ]]; do
case "$protocol_choice" in
"TCP")
	pattern_type_prompt
	case "$pattern_type_choice" in
	    "ASCII")
		    pattern_prompt "ASCII"
		    ;;
	    "HEX")
		    hex_pattern_prompt
		    ;;
	esac
	offset_number_prompt
	direction_prompt
	case "$direction_choice" in
		"CLIENT" )
			output_port_pattern_client
		    ;;
		"SERVER" )
			port_numbers_prompt
			output_port_pattern_server
		    ;;
	esac
	;;
"UDP")
	pattern_type_prompt
	case "$pattern_type_choice" in
	    "ASCII")
		    pattern_prompt "ASCII"
    		;;
	    "HEX")
		    hex_pattern_prompt
	    	;;
	esac
	offset_number_prompt
	direction_prompt
	case "$direction_choice" in
		"CLIENT")
			output_port_pattern_client
    		;;
		"SERVER")
			port_numbers_prompt
			output_port_pattern_server
	    	;;
	esac
	;;
"HTTP")
	http_pattern_type_prompt
    pattern_prompt "$pattern_type_choice"
    case "$pattern_type_choice" in
        "URL")
            output_http_url_pattern
            ;;
        "User Agent")
            output_http_useragent_pattern
            ;;
        "Content Type")
            output_http_contenttype_pattern
            ;;
    esac
    # we need to remember this as we add patterns for client and/or server
	set_client_vs_server "SERVER"
	;;
"SSL")
	ssl_pattern_type_prompt
	pattern_prompt "$pattern_type_choice"
    case "$pattern_type_choice" in
        "Host")
            output_ssl_host_pattern
            ;;
        "Common Name" | "Organizational Unit")
            output_ssl_cn_pattern
            ;;
    esac
    # we need to remember this as we add patterns for client and/or server
	set_client_vs_server "SERVER"
	;;
"SIP")
	sip_pattern_type_prompt
	pattern_prompt "$pattern_type_choice"
    case "$pattern_type_choice" in
        "SIP Server")
            output_sip_server_pattern
            ;;
        "User Agent")
            output_sip_useragent_pattern
            ;;
    esac
    # we need to remember this as we add patterns for client and/or server
	set_client_vs_server "SERVER"
	;;
"RTMP")
	pattern_prompt "RTMP URL"
	output_rtmp_url_pattern
    # we need to remember this as we add patterns for client and/or server
	set_client_vs_server "SERVER"
	;;
"First Packet")
    first_packet_pattern_prompt
    port_numbers_prompt
    set_client_vs_server "SERVER"
    output_first_packet_pattern
    ;;
esac
# Ask if they want more than one protocol filter
protocol_prompt
done
##### Output the file with the optional pieces in this order
output_preamble
output_detectorinit_preamble
output_optional_client
output_optional_server
output_optional_http_url
output_optional_http_useragent
output_optional_http_contenttype
output_optional_ssl_host
output_optional_ssl_cn
output_optional_sip_useragent
output_optional_sip_server
output_optional_rtmp_url
output_optional_first_packet_pattern
output_detectorinit_postlude
output_detectorclean_preamble
output_detectorclean_postlude

echo "Successfully completed construction of:"
echo "   ${OUTPUTFILE}"
echo "When you add the .lua file, the AppId,"
echo -en "   \""
echo -n "${APPIDSTRING}"
echo -e "\","
echo "   will be the name reported as detected."
### end ###
