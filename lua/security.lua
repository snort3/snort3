---------------------------------------------------------------------------
-- enhanced security policy
-- use with -c snort.lua --tweaks security
---------------------------------------------------------------------------

arp_spoof = nil

ftp_server.check_encrypted = true

detection =
{
    pcre_match_limit = 3500,
    pcre_match_limit_recursion = 3500
}

http_inspect.decompress_pdf = true
http_inspect.decompress_swf = true
http_inspect.decompress_zip = true

imap.decompress_pdf = true
imap.decompress_swf = true
imap.decompress_zip = true

pop.decompress_pdf = true
pop.decompress_swf = true
pop.decompress_zip = true

port_scan = nil

smtp.decompress_pdf = true
smtp.decompress_swf = true
smtp.decompress_zip = true

stream_ip.min_frag_length = 100

telnet.check_encrypted = true
telnet.normalize = true

