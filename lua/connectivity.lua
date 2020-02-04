---------------------------------------------------------------------------
-- reduced security policy that favors connectivity
-- use with -c snort.lua --tweaks connectivity
---------------------------------------------------------------------------

arp_spoof = nil

http_inspect.request_depth = 300
http_inspect.response_depth = 500

http_inspect.unzip = false
http_inspect.utf8 = false

port_scan = nil

stream_ip.min_frag_length = 16

