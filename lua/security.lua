---------------------------------------------------------------------------
-- enhanced security policy
-- use with -c snort.lua --tweaks security
---------------------------------------------------------------------------

ftp_server.check_encrypted = true

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

stream_tcp.require_3whs = 180

stream_tcp.small_segments =
{
    count = 3,
    maximum_size = 150,
}

telnet.check_encrypted = true
telnet.normalize = true

