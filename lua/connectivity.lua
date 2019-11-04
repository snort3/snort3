---------------------------------------------------------------------------
-- reduced security policy that favors connectivity
-- use with -c snort.lua --tweaks connectivity
---------------------------------------------------------------------------

http_inspect.request_depth = 300
http_inspect.response_depth = 500

http_inspect.unzip = false
http_inspect.utf8 = false

normalizer.tcp =
{
    ips = false,
    rsv = false,
    pad = false,
    req_urg = false,
    req_pay = false,
    req_urp = false,
    block = false,
}

port_scan = nil

